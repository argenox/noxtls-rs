# TLS 1.3 Interop and Release Verification Matrix

This template captures external TLS 1.3 validation runs beyond unit tests.

## How to use

1. Copy a row block per scenario.
2. Record **Pass / Fail / Skip** and attach artifacts (pcap, transcript hex, alert code).
3. Link failures to GitHub issues or internal tickets.

Automation command:

```powershell
pwsh -File scripts/run_tls13_interop_matrix.ps1
```

Release-gate command (required external rows):

```powershell
pwsh -File scripts/run_tls13_interop_matrix.ps1 -RequireExternal
```

Optional external harness hooks:

```powershell
pwsh -File scripts/run_tls13_interop_matrix.ps1 `
  -CNoxtlsTls13Command "<command that performs TLS13 C-peer client interop and returns non-zero on failure>" `
  -Tls13ZeroRttExternalCommand "<command that exercises external 0-RTT acceptance/replay behavior>" `
  -Tls13PqPureExternalCommand "<command that exercises pure ML-KEM-768 external interop>" `
  -Tls13PqHybridExternalCommand "<command that exercises hybrid X25519+ML-KEM-768 external interop>"
```

Default adapter script (auto-used when present):

- `scripts/run_c_peer_tls13.ps1`
- Reads command in this order: explicit `-Command`, `scripts/interop_harness.json`, env vars.
- Uses `NOXTLS_C_TLS13_E2_COMMAND`, `NOXTLS_C_TLS13_E3_COMMAND`, `NOXTLS_C_TLS13_E4_COMMAND`, and `NOXTLS_C_TLS13_E5_COMMAND` env vars.
- Start from `scripts/interop_harness.example.json` and save as `scripts/interop_harness.json`.

Artifact output:

- `artifacts/interop/tls13_matrix_results.json`

## Environment

| Field | Value |
|-------|-------|
| noxtls Rust commit | local workspace (uncommitted) |
| Peer (C noxtls / OpenSSL / mbedTLS / other) | OpenSSL loopback probe enabled; C/other peers still pending |
| OS / arch | Windows 10 (user workstation) |
| Date | 2026-05-09 |

## TLS 1.3 handshake scenarios

| # | Role | Suite | KX | Server cert | PSK / resumption | 0-RTT | Result | Notes |
|---|------|-------|-----|--------------|------------------|-------|--------|-------|
| 1 | Client | AES-128-GCM-SHA256 | X25519 | RSA-PSS-SHA256 | No | No | PASS (external OpenSSL loopback) | `TLS13-E1` in `scripts/run_tls13_interop_matrix.ps1` |
| 2 | Client | AES-256-GCM-SHA384 | X25519 | RSA-PSS-SHA384 | No | No | SKIP / FAIL in required mode | set `NOXTLS_C_TLS13_E2_COMMAND` (or pass `-CNoxtlsTls13Command`) to execute C-peer interop run |
| 3 | Client | CHACHA20-POLY1305 | X25519 | ECDSA P-256 | No | No | N/A | external peer not configured |
| 4 | Client | AES-128-GCM-SHA256 | secp256r1 | ECDSA P-256 | No | No | PASS (local) | covered by in-tree key-share and handshake-flight tests |
| 5 | Client | (preferred) | X25519 | (any) | Ticket | Yes | PASS (local) | covered by `tls13_early_data_*` and ticket tests |
| 6 | Client | (preferred) | X25519 | (any) | Ticket | No | PASS (local) | covered by ticket binder and resumption tests |
| 7 | Client | (preferred) | X25519 | (any) | Ticket | Yes | SKIP / FAIL in required mode | set `NOXTLS_C_TLS13_E3_COMMAND` (or pass `-Tls13ZeroRttExternalCommand`) for external 0-RTT validation |
| 8 | Client | AES-256-GCM-SHA384 | ML-KEM-768 (pure) | ML-DSA-65 | No | No | PASS (local) | `tls13_server_mlkem768_key_share_handshake_secret_derives` + in-house ML-KEM/ML-DSA backend |
| 9 | Client | AES-256-GCM-SHA384 | X25519+ML-KEM-768 (hybrid) | ML-DSA-65 | No | No | PASS (local) | `tls13_server_hybrid_key_share_handshake_secret_derives`; signature offer includes `0x0905` (`mldsa65`) |
| 10 | Client | AES-256-GCM-SHA384 | ML-KEM-768 (pure) | ML-DSA-65 | No | No | SKIP / FAIL in required mode | set `NOXTLS_C_TLS13_E4_COMMAND` or pass `-Tls13PqPureExternalCommand` for external PQ peer |
| 11 | Client | AES-256-GCM-SHA384 | X25519+ML-KEM-768 (hybrid) | ML-DSA-65 | No | No | SKIP / FAIL in required mode | set `NOXTLS_C_TLS13_E5_COMMAND` or pass `-Tls13PqHybridExternalCommand` for external PQ peer |

## PQ parity targets

| Target ecosystem | Hybrid KEX parity | Pure PQ KEX parity | PQ signature parity | Status | Notes |
|---|---|---|---|---|---|
| OQS/OpenSSL provider | Implemented (local) | Implemented (local) | Implemented (local) | External pending | wire paths are in-tree with in-house primitives; enable `TLS13-E4`/`TLS13-E5` harness commands |
| rustls PQ ecosystem | Planned | Planned | Planned | Pending external run | track draft/private codepoint alignment before external runs |
| BoringSSL PQ variants | Planned | Planned | Planned | Pending external run | requires compatible peer harness and feature profile mapping |
| wolfSSL PQ support | Planned | Planned | Planned | Pending external run | requires configured peer endpoint in matrix automation |

## Negative / robustness

| # | Scenario | Expected | Result |
|---|----------|----------|--------|
| N1 | Malformed ClientHello extension lengths | Reject / alert | PASS (local tests) |
| N2 | Truncated CertificateVerify | Parse failure | PASS (local tests) |
| N3 | Wrong binder | Handshake failure | PASS (local tests) |

## Fuzzing and long-run

| Campaign | Tool | Corpus seed | Duration | Triaged issues |
|----------|------|---------------|----------|----------------|
| Handshake parser | Rust unit-test malformed corpus | in-tree negative matrices | CI test runtime | no crashes observed in unit test campaign |
| Record decoder | Rust unit-test malformed corpus | in-tree record/alert/replay tests | CI test runtime | no crashes observed in unit test campaign |

## Sign-off

| Role | Name | Date |
|------|------|------|
| Engineering | | |
| Security review | | |
