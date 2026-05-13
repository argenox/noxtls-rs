---
sidebar_position: 15
title: Host gateway
---

# Host gateway

A **host gateway** runs NoxTLS Rust on a full OS and fronts one or more device protocols (MQTT over TLS, HTTPS, custom framing). This page captures integration decisions that differ from bare-metal firmware.

## Typical topology

```text
Devices (DTLS or proprietary)  →  Gateway (NoxTLS Rust, std + tokio)
                                        ↓
                                  Cloud (TLS 1.2/1.3)
```

## Recommended feature set

- **`std` + `alloc`** — default for host.
- **`adapter-tokio`** — when the gateway async runtime is Tokio-based.
- **Optional `provider-psa` or HSM** — when private keys for cloud-facing sessions live in hardware.

## Operational concerns

- **Connection fan-out** — size thread pools and handshake concurrency; use backpressure toward devices.
- **Logging** — scrub secrets; align with SOC retention policy.
- **Certificate rotation** — automate ACME or internal PKI workflows independent of device OTA cycles.

## Observability

Correlate gateway TLS session IDs with device identifiers in your observability backend. If you attach debug tooling, gate it behind compile-time features so production images stay lean.

## See also

- [Applications overview](./overview)
- [TLS API overview](../tls-api/overview)
- [Architecture](../architecture)
