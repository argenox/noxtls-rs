---
title: Apps and demos
---

# Apps and demos (`noxtls-test`)

This page maps application/demo entry points that are currently available in the Rust workspace.

## Crate metadata

- Workspace path: `crates/noxtls-test`
- Package name: `noxtls-test`
- Publish status: internal/private

## Binaries

- `tls_test` - TLS 1.3 modeled session and record-layer flow demo
- `sha_demo` - SHA-256 sanity check utility
- `perf_baseline` - micro-benchmark for SHA-256 and ChaCha20 throughput

## Run locally

From repository root:

```powershell
cargo run -p noxtls-test --bin tls_test
cargo run -p noxtls-test --bin sha_demo
cargo run -p noxtls-test --bin perf_baseline
```

## Source and references

- docs.rs: not published (internal crate)
- Source: [`crates/noxtls-test`](https://github.com/Argenox/noxtls-oem-rust/tree/main/crates/noxtls-test)

## Notes

`noxtls-test` is intentionally internal and may change faster than public crate APIs. Use this page as an examples index, and use topic pages under `api/` for stable API guidance.
