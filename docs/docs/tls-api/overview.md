---
sidebar_position: 11
title: TLS API overview
---

# TLS API overview

This section documents how **applications and firmware** interact with NoxTLS Rust for TLS 1.2 / 1.3 and DTLS. It provides the canonical API narrative with **device-relevant** grouping: what types matter, when to call them, and where to read deeper.

## Entry points

| Concern | Primary types / modules | Doc depth |
| ------- | ----------------------- | --------- |
| Modeled connection | `noxtls::Connection`, `HandshakeState`, `TlsVersion` | Rustdoc + examples in repo |
| Record layer helpers | `ProtectedRecord`, seal/open helpers exported from `noxtls` | Topic: [TLS topic](../api/tls) |
| DTLS | `DtlsOperationalPolicy`, replay trackers, flight helpers | Topic: [TLS topic](../api/tls) |
| Certificates | Parsed chains, hostname checks | [X.509 topic](../api/x509) |

## Handshake lifecycle (conceptual)

1. **Build client/server context** — versions, cipher suites, trust anchors, and optional session tickets.
2. **Drive handshake** — feed records from your transport; advance `HandshakeState` until `Finished` (or terminal error).
3. **Application data** — seal/open application records with negotiated keys; respect MTU and fragmentation rules on DTLS.
4. **Renegotiation / resumption** — follow product policy; many embedded products disable renegotiation entirely.

## DTLS vs TLS on devices

- **DTLS** — expect loss, reordering, and duplication; size reassembly buffers to your network worst case.
- **TLS** — assume reliable byte stream below the record layer (TCP or an equivalent pipe).

Operational knobs are summarized in repository markdown `docs/DTLS13_OPERATIONAL_POLICY.md` (source tree), linked from the TLS topic page where relevant.

## Deep dive

Continue to the **[TLS topic page](../api/tls)** for algorithm coverage, record layout notes, and cross-links to cryptography topics.

### Per-version and DTLS pages

- [DTLS](../api/dtls) · [TLS 1.0](../api/tls10) · [TLS 1.1](../api/tls11) · [TLS 1.2](../api/tls12) · [TLS 1.3](../api/tls13)
- [TLS 1.3 PQC](../api/tls13_pqc) · [Unified connection (OEM mapping)](../api/tls_unified)

For **crate-level** metadata (package description, features), use **Crate reference (generated)** under [Crypto API](../crypto-api/overview) in the sidebar—those pages are generated from `Cargo.toml` and are **supplemental**, not a substitute for this TLS API narrative.
