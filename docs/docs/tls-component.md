---
sidebar_position: 10
title: TLS component
---

# TLS component

The **TLS component** in NoxTLS Rust is the `noxtls` crate plus its tightly coupled dependencies (`noxtls-core`, `noxtls-crypto`, `noxtls-x509`, `noxtls-io`, `noxtls-platform`). On a **device**, you should think of it as the subsystem that owns:

- handshake state,
- record protection (AEAD / legacy where enabled),
- certificate authentication policy,
- optional DTLS retransmission and flight bookkeeping.

## Layered view

```text
Application (your code)
    → noxtls::Connection (modeled handshake + records; `TlsRecordDeframer` for wire deframing)
    → noxtls-io adapters (embedded-io / tokio / custom)
    → noxtls-platform (time; future RNG / storage hooks)
    → noxtls-crypto + noxtls-x509 (algorithms and PKIX)
```

## Device integration patterns

1. **Gateway** — Full `std` + `adapter-tokio` or blocking sockets; terminates TLS toward cloud and optional device-side DTLS.
2. **MCU client** — `no_std` + `alloc`, `adapter-embedded-io`, small trust store, pinned cipher suites.
3. **MCU server** — Rare; requires careful RAM for parallel handshakes and cert handling; see [Memory Usage](./memory-usage).

## Relationship to “TLS API”

- This page is the **component** narrative (roles, data flow, deployment).
- [TLS API](./tls-api/overview) is the **API surface** narrative (types, handshake phases, record helpers, and links into topic docs).

## Next reading

- [Architecture](./architecture) — crate boundaries.
- [TLS API overview](./tls-api/overview) — entry point for API topics.
- [Applications](./applications/overview) — end-to-end product patterns.
