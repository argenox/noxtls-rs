# Security Policy

## Reporting a vulnerability

Please report potential vulnerabilities privately to the maintainers.

- Do not open public issues for unpatched vulnerabilities.
- Include affected crate(s), version(s), reproduction details, and impact.
- Include any proof-of-concept input or trace if available.

## Scope

Security reports are accepted for all crates in this workspace:

- `noxtls` (TLS/DTLS protocol stack)
- `noxtls-core`
- `noxtls-crypto` (hash, symmetric, PKC, DRBG)
- `noxtls-pem`
- `noxtls-x509`
- `noxtls-io`
- `noxtls-platform`

Internal-only crate (`noxtls-test`) is lower priority but may still be reported if it affects shipped integrations.
