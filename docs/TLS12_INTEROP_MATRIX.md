# TLS 1.2 / DTLS 1.2 Interop Matrix

Last updated: 2026-05-09

Use this template to capture scenario-level interoperability outcomes for TLS 1.2 and DTLS 1.2.

## Legend

- PASS: Behavior matches expected semantics.
- FAIL: Interop failure or protocol mismatch.
- N/A: Scenario not applicable for the stack profile.
- SKIP: Scenario intentionally skipped because required external harness/runtime is unavailable.

Automation command:

```powershell
pwsh -File scripts/run_tls12_interop_matrix.ps1
```

Optional external harness hooks:

```powershell
pwsh -File scripts/run_tls12_interop_matrix.ps1 `
  -CNoxtlsTls12Command "<command that performs TLS12 C-peer client interop and returns non-zero on failure>" `
  -Dtls12ExternalCommand "<command that exercises DTLS12 loss/reorder external behavior>"
```

Default adapter script (auto-used when present):

- `scripts/run_c_peer_tls12_dtls12.ps1`
- Reads command in this order: explicit `-Command`, `scripts/interop_harness.json`, env vars.
- Uses `NOXTLS_C_TLS12_E2_COMMAND` and `NOXTLS_C_DTLS12_E1_COMMAND` env vars.
- Start from `scripts/interop_harness.example.json` and save as `scripts/interop_harness.json`.

Artifact output:

- `artifacts/interop/tls12_matrix_results.json`

## TLS 1.2 matrix

| Scenario | Local role | Peer stack | Cipher suite | Cert mode | Result | Notes / delta |
|----------|------------|------------|--------------|-----------|--------|---------------|
| Full handshake + app data | Client | C `noxtls` | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Server-auth | SKIP | Set `NOXTLS_C_TLS12_E2_COMMAND` (or pass `-CNoxtlsTls12Command`) to execute C-peer interop run |
| Full handshake + app data | Server | C `noxtls` | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Server-auth | N/A | Requires external C harness not present in current workspace |
| Full handshake + app data | Client | OpenSSL loopback | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Server-auth | PASS (external OpenSSL loopback) | `TLS12-E1` in `scripts/run_tls12_interop_matrix.ps1` |
| Full handshake + app data | Server | External peer | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Server-auth | N/A | Requires external peer runtime |
| SHA-384 suite negotiation | Client | C `noxtls` | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | Server-auth | N/A | Requires external C harness not present in current workspace |
| SHA-384 suite negotiation | Server | C `noxtls` | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | Server-auth | N/A | Requires external C harness not present in current workspace |

## DTLS 1.2 matrix

| Scenario | Local role | Peer stack | Loss/reorder profile | Result | Notes / delta |
|----------|------------|------------|----------------------|--------|---------------|
| Handshake + app data | Client | C `noxtls` | none | N/A | Requires external C harness not present in current workspace |
| Handshake + app data | Server | C `noxtls` | none | N/A | Requires external C harness not present in current workspace |
| Retransmit behavior | Client | C `noxtls` | 10% loss | SKIP | Set `NOXTLS_C_DTLS12_E1_COMMAND` (or pass `-Dtls12ExternalCommand`) for DTLS external loss/reorder run |
| Retransmit behavior | Server | C `noxtls` | 10% loss | N/A | Requires external C harness and network-loss simulation |
| Replay resistance | Server | C `noxtls` | duplicate packets | PASS (local) | Covered by `dtls13_connection_record_rejects_replay` and DTLS replay-window tests in `protocol/tests.rs` |

## Required artifact links

- Transcript captures: local unit-test transcript evidence only (no cross-stack capture)
- Failure logs: N/A (no external peer run executed)
- Packet captures: N/A (no external socket-level run executed)
- Test command output: `cargo test -p noxtls --lib`, `scripts/run_tls12_verification.ps1`

