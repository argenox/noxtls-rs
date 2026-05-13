---
sidebar_position: 13
title: Applications overview
---

# Applications overview

**Applications** here means **product-level patterns** that use NoxTLS Rust—not individual Cargo examples. Each pattern links host concerns, device firmware, and operations.

## Patterns in this section

| Page | Use case |
| ---- | -------- |
| [Firmware integration](./firmware-integration) | MCU or RTOS image: footprint, adapters, cert stores, update channels. |
| [Host gateway](./host-gateway) | Linux/Windows service terminating TLS toward cloud and device fleets. |
| [Apps topic (examples index)](../api/apps) | Repository examples and how to run them locally. |

## Lifecycle alignment

1. **Provisioning** — factory keys, trust anchors, and identity certs.
2. **Boot & update** — secure boot policies, signed OTA, and TLS for update servers.
3. **Runtime** — telemetry, command/control, and mutual TLS where required.

## Cross-links

- [Porting Guide](../porting-guide) — bring-up checklist.
- [TLS component](../tls-component) — where TLS logic sits in your architecture.
- [Security](../security) — coordinated disclosure and hardening.
