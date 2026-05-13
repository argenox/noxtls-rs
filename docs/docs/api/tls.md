---
title: TLS API (noxtls)
---

# TLS API (`noxtls`)

This page documents the primary TLS/DTLS functions exposed by `noxtls`, with parameter-level notes for integration code.

## Core types

- `Connection` — protocol state machine (TLS 1.2/1.3 + DTLS).
- `TlsVersion`, `HandshakeState`, `CipherSuite` — protocol selection and lifecycle.
- `ProtectedRecord` — encrypted record output/input for data plane calls.

## Connection lifecycle APIs

### `Connection::new`

```rust
pub fn new(version: TlsVersion) -> Self
```

- **`version`**: selects TLS 1.2 / TLS 1.3 / DTLS behavior.
- Initializes handshake/data state, transcript tracking, and operational defaults.

### `Connection::set_tls13_server_name`

```rust
pub fn set_tls13_server_name(&mut self, server_name: Option<&str>) -> Result<()>
```

- **`server_name`**: SNI DNS name; `None` disables SNI.
- Validates non-empty, DNS-compatible, max 65535 bytes.

### `Connection::set_tls13_alpn_protocols`

```rust
pub fn set_tls13_alpn_protocols(&mut self, protocols: &[&str]) -> Result<()>
```

- **`protocols`**: ordered ALPN protocol IDs.
- Rejects empty entries, >255-byte IDs, and duplicates.

## Handshake APIs

### `Connection::send_client_hello_with_psk`

```rust
pub fn send_client_hello_with_psk(
    &mut self,
    random: &[u8],
    identity: &[u8],
    obfuscated_ticket_age: u32,
    psk: &[u8],
) -> Result<Vec<u8>>
```

- **`random`**: ClientHello random bytes (32-byte TLS random expected).
- **`identity`**: PSK/ticket identity bytes.
- **`obfuscated_ticket_age`**: ticket age for binder calculation.
- **`psk`**: key material used for binder auth.
- Returns encoded ClientHello handshake bytes.

### `Connection::send_client_hello_auto`

```rust
pub fn send_client_hello_auto(&mut self, drbg: &mut HmacDrbgSha256) -> Result<Vec<u8>>
```

- Uses DRBG to generate ClientHello random internally.
- Best default for device clients that already host a DRBG instance.

### `Connection::recv_server_hello`

```rust
pub fn recv_server_hello(&mut self, msg: &[u8]) -> Result<()>
```

- **`msg`**: encoded ServerHello handshake message.
- Validates state ordering and processes normal/HRR paths.

### `Connection::process_tls12_server_handshake_flight`

```rust
pub fn process_tls12_server_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()>
```

- **`messages`**: ordered TLS 1.2 server flight records/messages.
- Performs multi-step TLS 1.2 server-flight validation and state transitions.

### `Connection::build_server_hello`

```rust
pub fn build_server_hello(
    version: TlsVersion,
    suite: CipherSuite,
    random: &[u8],
) -> Result<Vec<u8>>
```

- Utility constructor for explicit ServerHello generation (interop/tests/custom flows).

## Record/data APIs

### `Connection::seal_record`

```rust
pub fn seal_record(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<ProtectedRecord>
```

- **`plaintext`**: application payload.
- **`aad`**: additional authenticated data.
- Requires `HandshakeState::Finished`; enforces configured record size limits.

### `Connection::open_record`

```rust
pub fn open_record(&mut self, record: &ProtectedRecord, aad: &[u8]) -> Result<Vec<u8>>
```

- **`record`**: protected record from peer.
- **`aad`**: AAD used during peer seal.
- Verifies sequence ordering and decrypts peer record.

### `Connection::send_tls13_alert_packet`

```rust
pub fn send_tls13_alert_packet(
    &mut self,
    level: AlertLevel,
    description: AlertDescription,
    aad: &[u8],
) -> Result<Vec<u8>>
```

- Encodes and seals TLS 1.3 alert records.
- Use for explicit alert signaling in custom transports.

## DTLS packet helpers

```rust
pub fn noxtls_encode_dtls_record_header(header: DtlsRecordHeader) -> Result<[u8; DTLS_RECORD_HEADER_LEN]>
pub fn noxtls_encode_dtls_record_packet(
    content_type: RecordContentType,
    version: [u8; 2],
    epoch: u16,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>>
pub fn noxtls_parse_dtls_record_packet(input: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)>
pub fn noxtls_parse_dtls12_handshake_fragment(input: &[u8]) -> Result<DtlsHandshakeFragment>
pub fn noxtls_reassemble_dtls12_handshake_fragments(
    fragments: &[Vec<u8>],
    max_message_len: usize,
) -> Result<(u8, u16, Vec<u8>)>
```

- Use these when integrating with custom datagram schedulers/retransmit pipelines.
- `max_message_len` is a critical anti-amplification/DoS bound for fragment reassembly.

## Per-version and DTLS pages

[DTLS](./dtls), [TLS 1.0](./tls10), [TLS 1.1](./tls11), [TLS 1.2](./tls12), [TLS 1.3](./tls13), [TLS 1.3 PQC](./tls13_pqc), [Unified connection (OEM mapping)](./tls_unified). See also [TLS API overview](../../tls-api/overview).
