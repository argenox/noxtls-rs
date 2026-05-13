---
sidebar_position: 4
---

# Security

## General

Security is primarily an operational discipline, not only an algorithm choice. Strong cryptography can still fail through weak key handling, permissive production settings, dependency drift, or inadequate incident response.

Production deployments should use secure defaults, least privilege, and strict environment separation. Development and staging should not reuse production credentials, trust anchors, or signing keys.

At a minimum:

- Use modern TLS versions and authenticated cipher suites.
- Keep dependencies/toolchains current and patch advisories quickly.
- Protect keys in secure storage where possible; never log secret material.
- Require explicit opt-in for weaker compatibility behaviors.
- Audit authentication, key-management, and config changes.
- Keep a documented incident and key-rotation procedure.

## Cryptography

Modern cryptography is dependable when selected and integrated correctly. Most failures come from misuse: weak randomness, disabled verification, nonce reuse, or relaxed compatibility settings left enabled in production.

Core expectations:

- Prefer AEAD modes (for example AES-GCM or ChaCha20-Poly1305) for confidentiality + integrity.
- Use a cryptographically secure DRBG for key and nonce generation.
- Validate certificate chains and hostnames in client flows.
- Avoid custom protocol deviations unless you have a formal interoperability requirement.

### TLS policy (secure by default)

NoxTLS Rust defaults to a modern profile posture. Legacy behavior is available only through explicit compile-time selection.

Security and compatibility controls are centered in `noxtls-core`:

- `policy-strict-constant-time`
- `policy-allow-legacy-algorithms`
- `policy-allow-sha1-signatures`

`policy-strict-constant-time` is intentionally incompatible with the permissive legacy/SHA-1 modes.

For profile and feature mapping details, see [Configuration Guide](./configuration-guide).

### Post-quantum deployment guidance

When enabling PQ/hybrid paths:

- Treat current interop identifiers as deployment-specific unless standard assignments are finalized for your target ecosystem.
- Prefer staged hybrid migration where compatibility is needed.
- Keep a compatibility fallback policy for peers that do not negotiate PQ paths.
- Include algorithm agility in certificate/key lifecycle planning.

### Side-channel security

Side-channel attacks recover secrets from implementation behavior (timing, cache effects, branch patterns, error channels), not by breaking the underlying mathematics.

Mitigations:

- Prefer constant-time secret handling paths.
- Avoid secret-dependent branching/table lookups in sensitive code paths.
- Isolate sensitive workloads on shared-host deployments when possible.
- Validate assumptions per target architecture; do not assume one platform's behavior generalizes to another.

For higher-assurance builds, prefer `policy-strict-constant-time`.

### Key security

Key management often determines real-world security outcomes:

- Generate keys from approved entropy/DRBG sources.
- Protect long-term private keys in secure element, HSM, TPM, or equivalent where available.
- Enforce lifecycle controls: generation, activation, rotation, revocation, backup, destruction.
- Separate long-term identity keys from ephemeral session keys.
- Never hardcode private keys in source, firmware defaults, or images.

### Memory security

Secrets remain vulnerable while resident in memory:

- Minimize in-memory lifetime of keying material.
- Zeroize temporary secret buffers promptly.
- Avoid unnecessary copies of private material.
- Redact sensitive fields from logs, crash reports, and telemetry.
- Disable or tightly control core dumps in production.

## Build and deployment

Build and release choices directly impact security posture:

- Treat warnings as actionable and document any suppressions.
- Apply consistent hardening settings in CI and release workflows.
- Keep debug/permissive feature sets out of production artifacts.
- Use reproducible build practices where operationally feasible.

For algorithm and primitive details, see [Crypto API](./crypto-api/overview).

## Security reporting and lifecycle

Report suspected vulnerabilities privately; avoid public issue disclosure before a coordinated fix is available.

- Include affected crate(s), version(s), deployment context, and reproduction details.
- Include impact assessment and, when possible, minimal proof-of-concept traces.
- Coordinate fixes across code, tests, docs, and release notes.
- Publish mitigation and affected-version guidance once patches are available.

See [Repository Security Policy](https://github.com/argenox/noxtls-rs/security/policy) and [Release Notes](./release-notes).
