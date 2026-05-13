---
sidebar_position: 5
title: Quantum Crypto
---

# Quantum Crypto

Post-quantum cryptography (PQC) addresses the long-term risk that large-scale quantum computers could break widely deployed public-key algorithms such as classic RSA and ECC. For device products with long support windows, planning for PQ migration is part of normal crypto lifecycle management.

## Why this matters

The most relevant near-term risk is **harvest now, decrypt later**:

- Encrypted traffic captured today may be decrypted in the future if classical key exchange becomes breakable.
- Long-lived identities, firmware signing roots, and backend trust anchors must remain trustworthy across multi-year product lifecycles.
- Regulated or safety-critical deployments often require demonstrable algorithm agility before migration deadlines.

Symmetric cryptography and hashes are less impacted, but key sizes and policies may still need updates as standards evolve.

## NoxTLS migration posture

NoxTLS is designed for algorithm agility rather than a single hardcoded profile. In practical terms:

- Prefer **hybrid key establishment** during migration (classical + post-quantum) where peer compatibility requires it.
- Keep a policy-controlled fallback path for peers that cannot yet negotiate PQ/hybrid suites.
- Treat deployment identifiers and interop details as environment-specific until your target ecosystem finalizes stable assignments.
- Separate rollout stages for protocol negotiation, certificate profile updates, and operational validation.

For policy flags and feature controls, see [Configuration Guide](./configuration-guide). For baseline operational controls, see [Security](./security).

## Deployment strategy (recommended)

1. Inventory all TLS endpoints and certificate chains in your product.
2. Classify links by confidentiality lifetime (short-lived telemetry vs long-term sensitive data).
3. Enable PQ/hybrid paths first on high-value channels with strict telemetry and rollback controls.
4. Validate interoperability against every peer class (device, gateway, cloud, manufacturing tools).
5. Promote from canary to fleet rollout only after handshake/error regressions are stable.

## Embedded and gateway considerations

- **Embedded devices**: prioritize deterministic memory budgeting and test footprint impact for PQ/hybrid handshakes.
- **Host gateways**: terminate mixed fleets and enforce negotiation policy to shield constrained devices from abrupt transitions.
- **Manufacturing/provisioning flows**: update certificate issuance and trust-anchor packaging alongside runtime protocol changes.

Use the [Memory Usage](./memory-usage) and [Porting Guide](./porting-guide) pages to plan footprint and integration validation while introducing PQ features.

## Operational checklist

- Define explicit allowed/disallowed algorithm policy per environment.
- Track cryptographic inventory (keys, cert profiles, trust stores) per release.
- Add regression tests for handshake negotiation and fallback behavior.
- Document deprecation timelines for non-PQ-compatible peer profiles.
- Rehearse incident response for algorithm-level rollbacks.

Quantum migration is not a one-time switch. Treat it as an ongoing security program with staged rollout, measurable compatibility gates, and auditable policy controls.
