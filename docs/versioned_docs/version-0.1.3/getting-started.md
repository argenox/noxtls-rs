---
sidebar_position: 2
---

# Getting Started

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

## Next steps

- [Architecture](/docs/architecture)
- [Security](/docs/security)
- [Embedded targets and I/O](/docs/embed-targets) — `no_std`, `alloc`, transport adapters
- [Crate API](/docs/api)
