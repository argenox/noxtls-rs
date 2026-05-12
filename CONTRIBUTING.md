# Contributing

## Build setup

1. Install stable Rust toolchain.
2. From repo root, run:

```powershell
cargo check --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets
```

## Pull request expectations

- Keep changes scoped to a single concern when possible.
- Add or update tests for behavior changes.
- Maintain pure Rust implementations for cryptographic primitives.
- Ensure no new lint warnings are introduced.
- New or moved `.rs` files must use the canonical NoxTLS file header (see `.cursor/skills/noxtls-port-standards/SKILL.md`); run `scripts/update-rust-file-headers.ps1` if you need to normalize headers after merges.
