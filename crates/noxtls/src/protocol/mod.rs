// Copyright (c) 2019-2026, Argenox Technologies LLC
// All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only OR LicenseRef-Argenox-Commercial-License
//
// This file is part of the NoxTLS Library.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by the
// Free Software Foundation; version 2 of the License.
//
// Alternatively, this file may be used under the terms of a commercial
// license from Argenox Technologies LLC.
//
// See `noxtls/LICENSE` and `noxtls/LICENSE.md` in this repository for full details.
// CONTACT: info@argenox.com

//! TLS/DTLS protocol logic: `Connection` state machine, record framing, DTLS datagram helpers, KDF labels,
//! PSK ticket cache, and deterministic key material for tests and tooling.

mod connection;
mod dtls;
mod handshake;
mod kdf;
mod key_provider;
mod keyshare;
#[cfg(feature = "provider-psa")]
mod psa_provider;
mod psk;
mod record;
#[cfg(test)]
mod security_review_tests;
mod state;
mod tls_wire;

pub use connection::{
    ClientHelloExtensions, ClientHelloInfo, Connection, DtlsOperationalPolicy,
    DtlsOperationalProfile, ProtectedRecord, Tls13EarlyDataOperationalPolicy,
    Tls13EarlyDataOperationalProfile, Tls13EarlyDataReplayState, Tls13EarlyDataTelemetry,
    Tls13OcspStapleVerification, Tls13OcspStapleVerifier, Tls13QuicInitialSecrets,
    Tls13QuicNextTrafficSecrets, Tls13QuicPacketProtectionKeys, Tls13QuicTrafficSecretSnapshot,
    TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT, TLS13_QUIC_EXPORTER_LABEL_SERVER_1RTT,
};
pub use dtls::{
    noxtls_dtls13_aes128gcm_record_size, noxtls_encode_dtls_record_header,
    noxtls_encode_dtls_record_packet, noxtls_open_dtls13_aes128gcm_record,
    noxtls_parse_dtls12_handshake_fragment, noxtls_parse_dtls_record_header,
    noxtls_parse_dtls_record_packet, noxtls_reassemble_dtls12_handshake_fragments,
    noxtls_seal_dtls13_aes128gcm_record, DtlsEpochReplayTracker, DtlsFlightRecord,
    DtlsFlightRetransmitTracker, DtlsRecordHeader, DtlsReplayWindow,
};
pub use kdf::{
    noxtls_hkdf_extract_for_hash, noxtls_hkdf_extract_with_salt_for_hash,
    noxtls_tls13_expand_label_for_hash, HashAlgorithm,
};
pub use key_provider::{
    ExternalKeyHandle, ExternalKeyProvider, KeyDecryptAlgorithm, KeyDecryptRequest,
    KeyDeriveAlgorithm, KeyDeriveRequest, KeySignAlgorithm, KeySignRequest, SoftwareKeyProvider,
};
pub use keyshare::{
    noxtls_derive_deterministic_p256_private, noxtls_derive_deterministic_x25519_private,
    noxtls_derive_tls13_p256_shared_secret, noxtls_derive_tls13_x25519_shared_secret,
    noxtls_tls13_client_hello_offers_supported_key_exchange,
    noxtls_tls13_key_share_group_supported, noxtls_tls13_signature_algorithm_supported,
};
#[cfg(feature = "provider-psa")]
pub use psa_provider::PsaExternalKeyProvider;
pub use psk::{ResumptionTicket, TicketStore, TicketUsagePolicy};
pub use state::{
    AlertDescription, AlertLevel, CipherSuite, HandshakeState, RecordContentType, TlsVersion,
};
pub use tls_wire::{
    split_tls13_handshake_payload, TlsRecordDeframer, TLS_MAX_RECORD_PAYLOAD_LEN,
    TLS_RECORD_HEADER_LEN,
};
