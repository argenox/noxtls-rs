---
sidebar_position: 2
---

# Getting Started

This guide covers **developer setup** on a host machine. When you move to **device firmware**, follow [Porting Guide](./porting-guide), [Configuration Guide](./configuration-guide), and [Memory Usage](./memory-usage) in addition to the build steps below.

## Prerequisites

- Rust stable toolchain (`rustup` + `cargo`)
- Git

## Build and test

From the repository root:

```powershell
cargo check --workspace
cargo test --workspace
```

## Formatting and linting

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets
```

## Generate documentation site content

From `noxtls/docs`:

```powershell
npm install
npm run docs:sync
npm run start
```

`docs:sync` regenerates:

- crate API pages under `docs/docs/api`
- release notes page from `docs/changelog.json`

## Device-oriented next steps

- [Porting Guide](./porting-guide) — checklist for MCU / RTOS integration.
- [Embedded targets and I/O](./embed-targets) — `no_std`, `alloc`, transport adapters.
- [TLS component](./tls-component) — where handshake and record logic live.
- [Applications](./applications/overview) — firmware and gateway patterns.

## Reference

- [Architecture](./architecture)
- [Security](./security)
- [Crypto API overview](./crypto-api/overview)
