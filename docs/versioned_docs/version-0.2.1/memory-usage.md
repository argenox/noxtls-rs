---
sidebar_position: 7
title: Memory Usage
---

# Memory Usage

Device teams need predictable **ROM** (code) and **RAM** (heap, stack, record buffers) when TLS is only one subsystem. This page documents a repeatable measurement method, practical tuning points, and the exact APIs/config knobs that influence footprint.

## Footprint drivers

| Area | Crates / knobs | Notes |
| ---- | -------------- | ----- |
| Protocol + state machine | `noxtls` | TLS 1.2/1.3 and DTLS paths; handshake buffers dominate peak RAM. |
| Crypto | `noxtls-crypto` | AEAD, ECDH, signatures; ML-KEM / ML-DSA add code size. |
| X.509 | `noxtls-x509`, `noxtls-pem` | Chain depth and parser tables affect ROM; PEM is optional if you ingest DER only. |
| I/O adapters | `noxtls-io` | Thin; async stacks may pull larger dependency trees on host. |

## Build profiles to measure

```bash
cargo build -p noxtls --release --no-default-features --features alloc,adapter-embedded-io
```

Use at least two profiles for apples-to-apples comparisons:

- **Baseline TLS**: only the features your product ships.
- **Worst-case debug**: include DTLS, certificate validation, and optional algorithms you might enable in field variants.

Then use `llvm-size` / `cargo bloat` on the produced artifact.

## Runtime RAM checkpoints (recommended)

Capture RAM at these protocol milestones:

1. **Connection init** (`Connection::new`) to establish baseline.
2. **ClientHello/ServerHello phase** (`send_client_hello_*`, `recv_server_hello`) for first handshake growth.
3. **Certificate processing** (`recv_certificate`, chain validation) for peak parsing allocations.
4. **Finished + data path** (`seal_record`, `open_record`) for steady-state buffers.
5. **DTLS retransmit window** (`DtlsFlightRetransmitTracker`) for lossy-network worst-case.

## APIs and knobs affecting memory

### Record/data plane

- `Connection::set_max_record_plaintext_len(&mut self, max_len: usize) -> Result<()>`
  - Caps per-record plaintext accepted by `seal_record` / `open_record`.
  - Directly reduces peak per-record temporary buffer requirements.

### Handshake policy

- `Connection::set_dtls_operational_profile(...)`
- `Connection::set_dtls_operational_policy(...)`
  - Tune retransmit/backoff behavior and anti-amplification decisions.
  - Smaller retransmit windows reduce RAM but may reduce tolerance for loss/jitter.

### Certificate/X.509 overhead

- Prefer DER ingest APIs over PEM conversion when possible.
- Use minimal trust-anchor/intermediate sets for device images.
- Validate only required policy constraints for your deployment.

## Measuring on device

1. Link the **same feature set** you ship in production.
2. Capture **worst-case handshake** RAM (full chain, largest cert messages, retransmission windows for DTLS).
3. Add margin for **application records** and any middleware framing.

## Practical reduction checklist

- Drop unused **protocol versions** via `noxtls-core` profile flags when both peers are under your control.
- Prefer **DER-only** cert ingestion to avoid PEM tables if PEM is unused.
- Use **PSA offload** (`provider-psa`) to move keys and AEAD into secure hardware with a smaller Rust surface.
- Tune **record buffer sizes** and DTLS flight buffers per your [Architecture](./architecture) integration.

## Example measurement log template

Track each firmware profile with:

- Feature set / commit SHA
- `.text`, `.rodata`, `.data`, `.bss`
- Peak handshake RAM
- Steady-state per-session RAM
- DTLS loss simulation results (0%, 1%, 5% loss)

This keeps memory regressions reviewable across releases and aligns with the NoxTLS device-doc workflow.
