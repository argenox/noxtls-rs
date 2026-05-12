# TLS 1.3 Record Layer Policy (Modeled Stack)

This document captures the **ingress/egress contract** for the Rust `noxtls` TLS 1.3 record APIs so transport integrators can align buffers, fragmentation, and error handling.

## Wire expectations

- **Outer record**: TLS 1.2-style framing for compatibility (`legacy_record_version` 0x0303 for TLS 1.3 application data), AEAD tag at end of ciphertext.
- **Inner plaintext**: `TLSInnerPlaintext` — application payload, optional padding, trailing real content type byte.

## API-level limits

- **Plaintext cap**: `Connection::set_max_record_plaintext_len` (default 16_384 bytes, RFC maximum).
- **Sequence numbers**: Monotonic per direction; exhaustion returns a deterministic error before wrap.
- **0-RTT**: `set_tls13_require_early_data_acceptance`, `accept_tls13_early_data_with_ticket_policy` / `_with_ticket_store`, ticket `max_early_data_size` enforcement, server-flight packet ingest helpers, and optional anti-replay disable for lab use only.

## Transport integration checklist

1. Feed complete TLS records (or use fragmentation helpers) before calling decrypt APIs.
2. Treat **fatal alerts** as terminal for the connection state machine unless explicitly reset.
3. For TLS 1.3 early-data, use ticket-backed ClientHello (`early_data` extension) and EncryptedExtensions acknowledgment before exposing 0-RTT plaintext.
4. For DTLS 1.3, use `protocol::dtls` helpers and epoch-aware replay trackers (separate from TLS stream framing).

## RFC wire-model notes

- Socket read coalescing / partial record staging is the responsibility of the embedder unless using `noxtls-io` adapters.
- Policy knobs for peer fragment pre-validation can be tuned further; see `TLS13_INTEROP_MATRIX.md` for companion validation coverage.
