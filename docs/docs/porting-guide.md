---
sidebar_position: 5
title: Porting Guide
---

# Porting Guide

This guide is a **from-scratch embedded integration playbook** for NoxTLS Rust. It focuses on what teams asked for most: **which files to create/modify**, the minimum configuration to boot, and how to wire transport and TLS state-machine calls on a device target.

## Before you start

Pick one integration mode:

| Mode | When to choose it | Core crates |
| ---- | ----------------- | ----------- |
| Full TLS/DTLS on device | Device terminates TLS itself | `noxtls`, `noxtls-core`, `noxtls-crypto`, `noxtls-x509`, `noxtls-io`, `noxtls-platform` |
| Crypto-only on device | TLS offloaded to gateway/modem; device still needs crypto/X.509 | `noxtls-crypto` (+ optional `noxtls-x509`, `noxtls-pem`) |

This page assumes **full TLS/DTLS on device**.

## Files to modify in your firmware project

Create or update these files in your own application repository:

1. `Cargo.toml` (project root)  
   - Add `noxtls` dependency with embedded-safe features.
2. `.cargo/config.toml`  
   - Set target, runner/linker, and panic profile for your MCU/RTOS toolchain.
3. `src/net_transport.rs` (or equivalent)  
   - Implement/adapt your socket/UART/radio link to a NoxTLS transport trait.
4. `src/tls_client.rs` or `src/tls_server.rs`  
   - Hold `Connection` lifecycle and handshake/data functions.
5. `src/certs.rs` (or config module)  
   - Store trust anchors / cert chains (prefer DER bytes on embedded).
6. `memory.x` / linker script (if applicable)  
   - Ensure RAM/flash layout leaves room for TLS handshake peaks.
7. Optional policy file (for host tooling): `config/noxtls_config.h`-style text  
   - Parse with `LibraryConfig::from_mbedtls_style_str` when migrating legacy policy symbols.

## 1) Configure dependencies (`Cargo.toml`)

For blocking embedded I/O adapters:

```toml
[dependencies]
noxtls = { version = "0.2.1", default-features = false, features = ["alloc", "adapter-embedded-io"] }
```

For async embedded I/O adapters:

```toml
[dependencies]
noxtls = { version = "0.2.1", default-features = false, features = ["alloc", "adapter-embedded-io-async"] }
```

Why this matters:

- `default-features = false` removes `std`.
- `alloc` is required for protocol buffers (`Vec`, handshake messages, cert parsing).
- Adapter features are forwarded through `noxtls-io`.

## 2) Target config (`.cargo/config.toml`)

Add your target-specific configuration (example skeleton):

```toml
[build]
target = "thumbv7em-none-eabihf"

[target.thumbv7em-none-eabihf]
runner = "probe-rs run --chip YOUR_CHIP"
```

If you use panic-abort profiles, make sure your `Cargo.toml` profile sections match your runtime strategy.

## 3) Transport wiring (`src/net_transport.rs`)

NoxTLS I/O surfaces are in `noxtls::transport`:

- Blocking: `transport::blocking::BlockingStream`
- Async: `transport::stream_async::AsyncByteStream`
- Embedded adapters:
  - `transport::embedded_io_adapter::EmbeddedIoTransport`
  - `transport::embedded_io_async_adapter::EmbeddedIoAsyncTransport`
- Optional exact-length read helper (blocking): `transport::drive::noxtls_read_exact_blocking` (see [Embedded targets and I/O](./embed-targets))

If your network stack already implements `embedded-io` `Read`/`Write`, wrap it directly:

```rust
use noxtls::transport::embedded_io_adapter::EmbeddedIoTransport;

// your_socket implements embedded_io::Read + embedded_io::Write
let transport = EmbeddedIoTransport::new(your_socket);
```

If it does not, create a small adapter type implementing `BlockingStream` (or async trait) and convert your driver-specific errors into `TransportError`.

## 4) TLS state machine file (`src/tls_client.rs`)

A minimal client flow should:

1. Create `Connection::new(TlsVersion::Tls13)` (or `Tls12`).
2. Configure policy knobs early (`set_tls13_server_name`, ALPN, record size limits).
3. Build and send ClientHello (`send_client_hello_auto` or explicit variants).
4. Feed peer handshake messages (`recv_server_hello`, certificate/finished processing).
5. After `Finished`, use `seal_record` / `open_record` for application traffic.

The `examples/tls_client.rs` file in this repository is a good baseline for sequence and API naming.

## 5) Certificates and trust anchors (`src/certs.rs`)

Recommended embedded approach:

- Store certs as DER byte arrays in flash.
- Parse/validate using `noxtls-x509` APIs.
- Avoid PEM parsing on-device unless you truly need runtime text ingest.

Useful APIs:

- `noxtls_parse_certificate`
- `noxtls_validate_certificate_chain` / `noxtls_validate_certificate_chain_with_options`
- `noxtls_certificate_matches_hostname`

## 6) Legacy config migration (optional)

If migrating from C-style `NOXTLS_*` defines, parse text policy with:

- `LibraryConfig::from_mbedtls_style_str` (works in no_std + alloc)
- `LibraryConfig::from_mbedtls_style_file` (std-only host/tooling paths)

This helps preserve profile/policy parity while moving to Cargo features.

## 7) DTLS-specific embedded notes

For lossy links (radio/UDP):

- Configure DTLS operational policy/profile before production rollout.
- Budget RAM for fragmented handshake reassembly and retransmit flight tracking.
- Use bounded reassembly (`noxtls_reassemble_dtls12_handshake_fragments` with conservative max length).

## Bring-up checklist (practical)

1. `cargo check` with no default features:
   - `cargo check --no-default-features --features alloc,adapter-embedded-io`
2. Run host-side smoke test of your TLS state machine file.
3. Flash device and verify handshake + one protected record round-trip.
4. Validate cert path and hostname checks with production-like anchor set.
5. Measure handshake peak RAM and steady-state record RAM.
6. Freeze feature/profile set in CI to prevent accidental surface growth.

## Next steps

- [Configuration Guide](./configuration-guide) — feature matrix and policy.
- [Architecture](./architecture) — crate graph and dependency rules.
- [TLS component](./tls-component) — how the protocol crate composes record and handshake paths.
- [Embedded targets and I/O](./embed-targets) — adapter details and no_std notes.
- [Memory Usage](./memory-usage) — footprint measurement and tuning workflow.
