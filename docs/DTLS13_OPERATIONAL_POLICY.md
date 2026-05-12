# DTLS 1.3 Operational Policy

Last updated: 2026-05-08

## Purpose

This document defines transport-facing retry/timeout knobs for DTLS active flights and retransmit scheduling.

## API surface

- `Connection::dtls_operational_policy()`
- `Connection::set_dtls_operational_policy(...)`
- `Connection::apply_dtls_operational_profile(...)`

Types:

- `DtlsOperationalPolicy`
- `DtlsOperationalProfile::{Conservative, LanLowLatency, LossyNetwork}`

## Default behavior

On DTLS connections, `Conservative` defaults are:

- `retransmit_initial_timeout_ms = 1000`
- `max_retransmit_attempts = 4`
- `active_flight_timeout_ms = 10000`

These map to the existing retransmit scheduler and active-flight timeout logic used by:

- `poll_dtls12_due_retransmit_packets`
- `poll_dtls13_active_flight_due_packets`

## Guidance

- Use `LanLowLatency` for low-loss datacenter or local-network links.
- Use `LossyNetwork` for WAN/mobile links with expected packet loss and reordering.
- Apply explicit `DtlsOperationalPolicy` values for deployment-specific SLO tuning.
