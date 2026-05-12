# DTLS Performance Baseline

Last updated: 2026-05-10

## Scope

This report captures reproducible Rust-vs-C baseline comparisons for DTLS-capable crates.

## Environment

- Host: Windows 10 workstation
- Build profile: `release`
- Runner: `scripts/run_dtls_perf_baseline.ps1`
- Harness config: `scripts/perf_harness.json`

## Measurements

- Rust (`cargo test -p noxtls --lib --release`): `3.744s`
- Rust (`cargo test -p noxtls-crypto --lib --release`): `1.57s`
- C baseline (`noxtls_lib_release`): `18.0s`
- C baseline (`noxtls_crypto_lib_release`): `3.5s`
- Ratio vs C (`noxtls_lib_release`): `0.208`
- Ratio vs C (`noxtls_crypto_lib_release`): `0.4486`
- Threshold policy (`max_runtime_regression_ratio_vs_c`): `1.5`
- Gate result: `PASS`

## Artifacts

- Latest JSON artifact: `artifacts/perf/dtls_perf_baseline.json`
- Re-run command:
  `powershell -ExecutionPolicy Bypass -File scripts/run_dtls_perf_baseline.ps1`

## Follow-on expansion (non-blocking)

- Add packet-rate and handshake-latency focused DTLS microbenchmarks.
- Add memory-footprint thresholds alongside runtime ratios.
