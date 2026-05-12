---
sidebar_position: 6
---

# Embedded targets and I/O

This page summarizes how the Rust workspace supports `no_std`, bare-metal style builds, and transport integration.

## Feature flags (all library crates)

| Feature | Meaning |
| ------- | ------- |
| `std` (default) | Full standard library; file helpers and `std::error::Error` impls where applicable. |
| `alloc` (default) | Heap types (`Vec`, `String`) for cryptographic and protocol buffers. |

Disable defaults for bare-metal style builds:

```powershell
cargo check -p noxtls --no-default-features --features alloc
```

## `std`-only APIs

When `std` is disabled, the following are unavailable (use in-memory / slice APIs instead):

| Crate | API |
| ----- | --- |
| `noxtls-core` | `LibraryConfig::from_mbedtls_style_file` — use `from_mbedtls_style_str` with bytes you loaded. |
| `noxtls-x509` | `pem_file_to_der`, `pem_file_to_der_blocks`, `der_to_pem_file`, `der_to_file`. |
| `noxtls` | `TicketStore::save_to_file`, `TicketStore::load_from_file`. |

## TLS transport (`noxtls`)

The `transport` module defines:

- **`transport::blocking::BlockingStream`** — synchronous read/write.
- **`transport::stream_async::AsyncByteStream`** — async read/write (uses `async_trait(?Send)` for `embedded-io-async` compatibility).

Optional Cargo features on **`noxtls`** (forwarded to `noxtls-io`):

| Feature | Purpose |
| ------- | ------- |
| `adapter-embedded-io` | `EmbeddedIoTransport` wrapping `embedded-io` `Read` + `Write`. |
| `adapter-embedded-io-async` | `EmbeddedIoAsyncTransport` wrapping `embedded-io-async`. |
| `adapter-tokio` | `TokioAsyncTransport` for `tokio` types with `AsyncReadExt` + `AsyncWriteExt` (implies `std`). |

Example checks:

```powershell
cargo check -p noxtls --features adapter-embedded-io
cargo check -p noxtls --features adapter-embedded-io-async
cargo check -p noxtls --features adapter-tokio
```

## Handshake helpers

`transport::drive::read_exact_blocking` reads a fixed number of bytes through a `BlockingStream` for framing layers built on top of the protocol state machine.
