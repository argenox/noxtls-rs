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
mod state;

pub use connection::{
    ClientHelloExtensions, ClientHelloInfo, Connection, DtlsOperationalPolicy,
    DtlsOperationalProfile, ProtectedRecord, Tls13EarlyDataOperationalPolicy,
    Tls13EarlyDataOperationalProfile, Tls13EarlyDataReplayState, Tls13EarlyDataTelemetry,
    Tls13OcspStapleVerification, Tls13OcspStapleVerifier, Tls13QuicInitialSecrets,
    Tls13QuicNextTrafficSecrets, Tls13QuicPacketProtectionKeys, Tls13QuicTrafficSecretSnapshot,
    TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT, TLS13_QUIC_EXPORTER_LABEL_SERVER_1RTT,
};
pub use dtls::{
    dtls13_aes128gcm_record_size, encode_dtls_record_header, encode_dtls_record_packet,
    open_dtls13_aes128gcm_record, parse_dtls12_handshake_fragment, parse_dtls_record_header,
    parse_dtls_record_packet, reassemble_dtls12_handshake_fragments, seal_dtls13_aes128gcm_record,
    DtlsEpochReplayTracker, DtlsFlightRecord, DtlsFlightRetransmitTracker, DtlsRecordHeader,
    DtlsReplayWindow,
};
pub use kdf::{
    hkdf_extract_for_hash, hkdf_extract_with_salt_for_hash, tls13_expand_label_for_hash,
    HashAlgorithm,
};
pub use key_provider::{
    ExternalKeyHandle, ExternalKeyProvider, KeyDecryptAlgorithm, KeyDecryptRequest,
    KeyDeriveAlgorithm, KeyDeriveRequest, KeySignAlgorithm, KeySignRequest, SoftwareKeyProvider,
};
pub use keyshare::{
    derive_deterministic_p256_private, derive_deterministic_x25519_private,
    derive_tls13_p256_shared_secret, derive_tls13_x25519_shared_secret,
    tls13_client_hello_offers_supported_key_exchange, tls13_key_share_group_supported,
    tls13_signature_algorithm_supported,
};
#[cfg(feature = "provider-psa")]
pub use psa_provider::PsaExternalKeyProvider;
pub use psk::{ResumptionTicket, TicketStore, TicketUsagePolicy};
pub use state::{
    AlertDescription, AlertLevel, CipherSuite, HandshakeState, RecordContentType, TlsVersion,
};
