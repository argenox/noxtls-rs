---
sidebar_position: 4
---

# Security

## Reporting vulnerabilities

Please report potential vulnerabilities privately to maintainers.

- Do not open public issues for unpatched vulnerabilities.
- Include affected crate(s), versions, reproduction details, and impact.
- Include proof-of-concept input/trace where possible.

## Workspace security scope

- `noxtls`
- `noxtls-core`
- `noxtls-crypto`
- `noxtls-pem`
- `noxtls-x509`
- `noxtls-io`
- `noxtls-platform`

## Policy features

Security policy and compatibility controls are implemented as compile-time features in `noxtls-core`:

- `policy-strict-constant-time`
- `policy-allow-legacy-algorithms`
- `policy-allow-sha1-signatures`

Strict constant-time mode is intentionally incompatible with legacy/sha1 permissive modes.
