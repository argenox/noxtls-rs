# DTLS Stateful Fuzz Campaign Workflow

This document defines the sustained malformed-wire campaign workflow used to
close `TLS13:I2` and `TLS12:I12-2`.

## Runner

From repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_dtls_stateful_fuzz_campaign.ps1 -Iterations 200
```

The campaign writes reproducible artifacts under:

- `artifacts/fuzz/reports/` - campaign logs and JSON summaries
- `artifacts/fuzz/crashes/` - captured failing iteration logs
- `artifacts/fuzz/corpus/` - reserved corpus directory for promoted regressions

## Triage workflow

1. Open the latest `artifacts/fuzz/reports/*.json` summary.
2. If `failed > 0`, inspect corresponding logs in `artifacts/fuzz/crashes/`.
3. Reproduce locally with the same test target:
   - `cargo test -p noxtls --lib dtls_stateful_fuzz_smoke_`
4. Add/extend a named regression test in `oem/extensions/noxtls-oem-validation/suites/noxtls/protocol/tests.rs`.
5. Keep the failing payload and reproduction notes in `artifacts/fuzz/corpus/` for future replay.

## CI gate intent

`scripts/run_dtls_stateful_fuzz_campaign.ps1` is intended for scheduled/nightly
campaigns while `scripts/run_dtls_stateful_fuzz_smoke.ps1` remains the quick PR
smoke gate.
