# QUIC / HTTP3 Interop and Readiness Matrix

This matrix tracks QUIC-TLS and HTTP/3 readiness evidence for release planning.

## Automation

Run local vector/readiness evidence:

```powershell
pwsh -File scripts/run_quic_http3_interop_matrix.ps1
```

Require external harness scenarios to pass:

```powershell
pwsh -File scripts/run_quic_http3_interop_matrix.ps1 -RequireExternal
```

Optional external harness hooks:

```powershell
pwsh -File scripts/run_quic_http3_interop_matrix.ps1 `
  -QuicHttp3HandshakeExternalCommand "<external QUIC/HTTP3 handshake command>" `
  -QuicHttp3RequestExternalCommand "<external QUIC/HTTP3 request command>"
```

Default adapter script (auto-used when present):

- `scripts/run_quic_http3_peer.ps1`
- Reads command in this order: explicit `-Command`, `scripts/interop_harness.json`, env vars.
- Uses `NOXTLS_QUIC_H3_E1_COMMAND` and `NOXTLS_QUIC_H3_E2_COMMAND`.

Artifact output:

- `artifacts/interop/quic_http3_matrix_results.json`

## Environment

| Field | Value |
|---|---|
| noxtls Rust commit | local workspace (uncommitted) |
| Date | 2026-05-11 |
| OS / arch | Windows 10 (user workstation) |

## QUIC / HTTP3 scenarios

| # | Scenario | Result source | Status | Notes |
|---|---|---|---|---|
| 1 | QUIC v1 initial secret derivation vectors | `QUIC-L1` | PASS (local) | RFC 9001 sample vectors in OEM protocol suite |
| 2 | QUIC v1 packet protection key vectors | `QUIC-L2` | PASS (local) | RFC 9001 sample vectors in OEM protocol suite |
| 3 | QUIC key-update (`quic ku`) chain | `QUIC-L3` | PASS (local) | label chain regression in OEM protocol suite |
| 4 | QUIC exporter label enforcement | `QUIC-L4` | PASS (local) | exporter-prefix policy + output stability tests |
| 5 | HTTP/3 external handshake | `QUIC-H3-E1` | SKIP unless configured | configure external harness command for required mode |
| 6 | HTTP/3 external request/response | `QUIC-H3-E2` | SKIP unless configured | configure external harness command for required mode |

## Readiness interpretation

- **Not Missing**: local QUIC-TLS cryptographic readiness evidence exists and is reproducible.
- **Partial**: external HTTP/3 peer interop is harnessed but may remain pending until environment commands are configured.
- **Implemented**: both external scenarios pass in required mode (`-RequireExternal`).
