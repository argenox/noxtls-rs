---
sidebar_position: 14
title: Firmware integration
---

# Firmware integration

This page describes how to embed NoxTLS Rust into a **device firmware image** with predictable integration risk: memory, boot order, secure storage, and transport plumbing.

## Boot-time ordering

1. **Platform hooks** — Initialize `noxtls-platform` time sources before any TLS handshake that validates certificates or anti-replay windows.
2. **Trust store** — Load roots from flash or secure element; keep minimal set on device, fuller set on gateway if applicable.
3. **Networking stack** — Bring up L2/L3 and only then start TLS or DTLS listeners/clients.

## Storage layout

- **Read-only** segments: trust anchors, optional stapled OCSP policy tables.
- **Writable** segments: session tickets, counters, and DTLS replay state—size explicitly and wipe on factory reset.

## Transport binding

Choose one primary adapter and avoid mixing blocking/async models in the same task without a clear boundary:

- **Blocking MCU** — `adapter-embedded-io` with a dedicated worker loop.
- **Async MCU** — `adapter-embedded-io-async` with an executor you already ship.

## Validation matrix

| Test | Pass criteria |
| ---- | -------------- |
| Cold boot handshake | Completes within power budget; RAM peak under cap. |
| Flaky link (DTLS) | Retransmissions recover without deadlock; anti-replay holds. |
| Clock skew | Policy rejects or tolerates skew per product decision. |
| OTA during session | Defined behavior: drop, pause, or migrate sessions safely. |

## Related docs

- [Memory Usage](../memory-usage)
- [Configuration Guide](../configuration-guide)
- [Embedded targets and I/O](../embed-targets)
