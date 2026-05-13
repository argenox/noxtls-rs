---
title: DTLS
---

# DTLS

## Algorithm

**DTLS** (Datagram TLS) reuses TLS cipher suites and handshake transcripts over **UDP** (or similar datagram transports). Compared to stream TLS it adds:

- **Explicit record framing** so each datagram can be parsed independently (**13-byte** record headers in this implementation).
- **Epoch and sequence numbers** per record so keys can rotate and **replays** can be rejected within an epoch.
- **Handshake fragmentation** (DTLS 1.2 style) so large **`Certificate`** / **`CertificateVerify`** chains fit under the path MTU.
- **Retransmission and flight** logic at the application or connection layer, because datagrams are not reliably delivered.

NoxTLS implements **DTLS-oriented record encoding/decoding**, **DTLS 1.2 handshake fragment** helpers, **replay windows**, **flight retransmit tracking**, **DTLS 1.3 AES-128-GCM record** seal/open helpers, and **`Connection`** fields that carry DTLS epoch/sequence and timer state. Wire compatibility and full state-machine coverage should be validated against your target profile (see **[TLS](./tls)**).

## Purpose

Use these APIs when you integrate **`noxtls`** on a **datagram** transport: build or parse **DTLS records**, bound **handshake reassembly**, apply **anti-replay** checks, size **AEAD** packets, and tune **retransmit / flight timeouts** on a **`Connection`** configured for **`TlsVersion::Dtls12`** or **`TlsVersion::Dtls13`**.

## Rust API

- **Crate:** `noxtls` (types and functions are re-exported from the crate root).
- **Module path (implementation):** `noxtls::protocol` (see `protocol/dtls.rs` and DTLS fields on **`Connection`** in `protocol/connection.rs`).

### Record layer (DTLS 1.2 / 1.3 framing)

| Symbol | Role |
| --- | --- |
| **`DtlsRecordHeader`** | Parsed or built header: **`content_type`**, **`version`** (`[u8; 2]`, e.g. DTLS 1.2 `0xFEFD`, DTLS 1.3 `0xFEFC`), **`epoch`**, **`sequence`** (48-bit, must be **`≤ (1<<48)-1`**), **`length`** (payload length). |
| **`noxtls_encode_dtls_record_header(header) -> Result<[u8; 13]>`** | Serializes one header; errors if sequence is out of range. |
| **`noxtls_parse_dtls_record_header(input) -> Result<(DtlsRecordHeader, &[u8])>`** | Requires at least **13** bytes; rejects unknown **`RecordContentType`**. |
| **`noxtls_encode_dtls_record_packet(content_type, version, epoch, sequence, payload) -> Result<Vec<u8>>`** | **`header \|\| payload`**; **`payload`** length must fit in **`u16`** (same on-the-wire limit as TLS record length). |
| **`noxtls_parse_dtls_record_packet(input) -> Result<(DtlsRecordHeader, Vec<u8>)>`** | Parses header then checks **`body.len() == header.length`** (mitigates length-desync attacks). |

### DTLS 1.2 handshake fragmentation

| Symbol | Role |
| --- | --- |
| **`DtlsHandshakeFragment`** | Structured view of one fragment: **`handshake_type`**, 24-bit **`message_len`**, **`message_seq`**, **`fragment_offset`**, **`fragment_len`**, **`fragment_body`**. |
| **`noxtls_encode_dtls12_handshake_fragments(handshake_type, message_seq, body, max_fragment_len) -> Result<Vec<Vec<u8>>>`** | Splits a full handshake body into ordered **fragment records** (each **`12`-byte fragment header + body**). **`max_fragment_len`** must be **`> 0`**; total message length must fit in **24 bits**. |
| **`noxtls_parse_dtls12_handshake_fragment(input) -> Result<DtlsHandshakeFragment>`** | Validates header/body consistency and that **`offset + len ≤ message_len`**. |
| **`noxtls_reassemble_dtls12_handshake_fragments(fragments, max_message_len) -> Result<(u8, u16, Vec<u8>)>`** | Verifies all fragments share **type**, **`message_seq`**, and **`message_len`**, allocates **`message_len`** bytes, copies ranges, and requires **every byte** filled (**gap/overlap** detection via a **`filled`** bitmap). **`max_message_len`** caps allocation (**anti-amplification** style bound). |

### DTLS 1.3 AES-128-GCM records

| Symbol | Role |
| --- | --- |
| **`noxtls_dtls13_aes128gcm_record_size(plaintext_len) -> Result<usize>`** | Returns full wire size (**13-byte header + ciphertext + 16-byte tag**), checking **16-bit** limits and overflow. |
| **`noxtls_seal_dtls13_aes128gcm_record(epoch, sequence, key, static_iv, plaintext)`** | Builds **DTLS 1.3**-style **AES-GCM** record (**outer type** **`application_data`**, version **`0xFEFD`** on the wire in this helper), derives a **12-byte** nonce from **`static_iv`**, **`epoch`**, and **`sequence`**, with **AAD** = serialized **13-byte** header. |
| **`noxtls_open_dtls13_aes128gcm_record(packet, key, static_iv, replay_tracker)`** | Decrypt/verify; returns **`(DtlsRecordHeader, plaintext)`**. Enforces **`application_data`** type, version **`[0xFE, 0xFD]`**, and updates **`replay_tracker`** (**`StateError`** on replay or disallowed epoch/sequence). |

### Replay and retransmit primitives

| Symbol | Role |
| --- | --- |
| **`DtlsReplayWindow`** | **64-sequence** sliding bitmap vs **`latest_sequence`** (**`check_and_mark`** returns **`false`** on replay or stale sequences). **`snapshot` / `restore_from_snapshot`** for persistence. |
| **`DtlsEpochReplayTracker`** | Tracks **current** and **previous** epoch windows; **`check_and_mark(epoch, sequence)`** accepts replays only in allowed epochs. |
| **`DtlsFlightRetransmitTracker`** | Stores outbound packets by **`(epoch, sequence)`** with bounded history (**default cap `256`** in **`Connection`**), **ACK** marking, exponential backoff on **`collect_due_retransmit_packets`**, and pruning. |
| **`DtlsFlightRecord`** | One tracked outbound datagram and its retransmit schedule. |

### `Connection` policy (timers)

| Symbol | Role |
| --- | --- |
| **`DtlsOperationalPolicy`** | **`retransmit_initial_timeout_ms`**, **`max_retransmit_attempts`**, **`active_flight_timeout_ms`**. Zeros are **clamped to 1** when applied. |
| **`DtlsOperationalProfile`** | **`Conservative`**, **`LanLowLatency`**, **`LossyNetwork`** — preset triples mapped through **`set_dtls_operational_policy`**. |
| **`Connection::set_dtls_operational_policy` / `apply_dtls_operational_profile`** | Require **`version.is_dtls()`** (internal gate is named **`ensure_dtls12_mode`** but applies to any DTLS profile; **`StateError`** if the connection is stream TLS). **`active_flight_timeout_ms`** is also used for **DTLS 1.3** active-flight timers. |
| **`Connection::dtls_operational_policy`** | Returns **`Some(policy)`** only when **`version.is_dtls()`**; **`None`** for stream TLS. |

## Feature flags and policy

- **`noxtls-core`:** **`feature-dtls`** must be enabled for DTLS profile types in core configs. It is included in **`profile-default`** and **`profile-tls-server-pki`**, but **not** in **`profile-minimal-tls-client`** or **`profile-crypto-only`** (see [Build configuration](./build_config)). **`feature-dtls`** requires **`feature-tls`** (enforced at compile time in **`noxtls-core`**).
- **`noxtls`:** Enable the **`noxtls-core`** profile that includes DTLS if you strip default features; otherwise DTLS-specific **`TlsVersion`** paths may be unavailable.

## Examples

```rust
use noxtls::{noxtls_encode_dtls_record_packet, noxtls_parse_dtls_record_packet, RecordContentType};

// DTLS 1.2 record version bytes (example only).
let packet = noxtls_encode_dtls_record_packet(
    RecordContentType::ApplicationData,
    [0xfe, 0xfd],
    1,
    42,
    b"hello",
)
.unwrap();
let (_header, payload) = noxtls_parse_dtls_record_packet(&packet).unwrap();
assert_eq!(payload, b"hello");
```

See also repository **`examples/dtls_client.rs`** and **`examples/dtls_server.rs`** for end-to-end usage patterns.

## Security and compatibility

- **Length checks:** Always use **`noxtls_parse_dtls_record_packet`** (or header parse + explicit bound) so advertised **`length`** cannot drive unbounded reads off one UDP payload.
- **Handshake reassembly:** Pass a **`max_message_len`** aligned with your **MTU / amplification** policy; **`noxtls_reassemble_dtls12_handshake_fragments`** rejects oversized **`message_len`** and **incomplete** coverage.
- **Replay:** Use **`DtlsEpochReplayTracker`** (or equivalent) for inbound records per epoch; datagram duplication is common on the public Internet.
- **Retransmit:** **`DtlsFlightRetransmitTracker`** caps stored flights; tune **`max_records`** and **`max_retransmit_attempts`** so memory and retry storms stay bounded.
- **AEAD:** DTLS 1.3 record helpers assume **AES-128-GCM** with the **12-byte static IV** layout used in the implementation; confirm nonce/AAD rules match your interoperability profile.

## Related

- [TLS](./tls)
- [TLS API overview](../../tls-api/overview)
- [Build configuration](./build_config)
