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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![allow(clippy::incompatible_msrv)]
#![allow(clippy::redundant_guards)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::type_complexity)]
#![allow(clippy::useless_vec)]

//! User-facing TLS and DTLS protocol surface for the NoxTLS Rust port.
//!
//! This crate wires together a modeled `protocol` handshake and record layer, deterministic key-share
//! helpers for interop, optional PSK ticket persistence, and re-exports `noxtls_io::transport` adapters
//! for blocking, async, and embedded I/O profiles.

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod internal_alloc;
mod protocol;

pub use noxtls_io::transport;

/// Portable platform hooks (time, future RNG/storage traits).
pub use noxtls_platform as platform;

pub use protocol::{
    noxtls_derive_deterministic_p256_private, noxtls_derive_deterministic_x25519_private,
    noxtls_derive_tls13_p256_shared_secret, noxtls_derive_tls13_x25519_shared_secret,
    noxtls_dtls13_aes128gcm_record_size, noxtls_encode_dtls_record_header,
    noxtls_encode_dtls_record_packet, noxtls_hkdf_extract_for_hash,
    noxtls_hkdf_extract_with_salt_for_hash, noxtls_open_dtls13_aes128gcm_record,
    noxtls_parse_dtls12_handshake_fragment, noxtls_parse_dtls_record_header,
    noxtls_parse_dtls_record_packet, noxtls_reassemble_dtls12_handshake_fragments,
    noxtls_seal_dtls13_aes128gcm_record, noxtls_tls13_client_hello_offers_supported_key_exchange,
    noxtls_tls13_expand_label_for_hash, noxtls_tls13_key_share_group_supported,
    noxtls_tls13_signature_algorithm_supported, split_tls13_handshake_payload, AlertDescription,
    AlertLevel, CipherSuite, ClientHelloExtensions, ClientHelloInfo, Connection,
    DtlsEpochReplayTracker, DtlsFlightRecord, DtlsFlightRetransmitTracker, DtlsOperationalPolicy,
    DtlsOperationalProfile, DtlsRecordHeader, DtlsReplayWindow, ExternalKeyHandle,
    ExternalKeyProvider, HandshakeState, HashAlgorithm, KeyDecryptAlgorithm, KeyDecryptRequest,
    KeyDeriveAlgorithm, KeyDeriveRequest, KeySignAlgorithm, KeySignRequest, ProtectedRecord,
    RecordContentType, ResumptionTicket, SoftwareKeyProvider, TicketStore, TicketUsagePolicy,
    Tls13EarlyDataOperationalPolicy, Tls13EarlyDataOperationalProfile, Tls13EarlyDataReplayState,
    Tls13EarlyDataTelemetry, Tls13OcspStapleVerification, Tls13OcspStapleVerifier,
    Tls13QuicInitialSecrets, Tls13QuicNextTrafficSecrets, Tls13QuicPacketProtectionKeys,
    Tls13QuicTrafficSecretSnapshot, Tls13ServerIdentityKey, TlsRecordDeframer, TlsRole, TlsVersion,
    TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT, TLS13_QUIC_EXPORTER_LABEL_SERVER_1RTT,
    TLS_MAX_RECORD_PAYLOAD_LEN, TLS_RECORD_HEADER_LEN,
};

#[cfg(feature = "provider-psa")]
pub use noxtls_psa::{
    AeadEncryptRequest as PsaAeadEncryptRequest, AeadEncryptResponse as PsaAeadEncryptResponse,
    FfiPsaBackend, KeyDecryptRequest as PsaKeyDecryptRequest,
    KeyDeriveRequest as PsaKeyDeriveRequest, KeySignRequest as PsaKeySignRequest, PsaCryptoBackend,
    PsaDecryptAlgorithm, PsaDeriveAlgorithm, PsaError, PsaExternalKeyHandle, PsaProvider,
    PsaResultCode, PsaSignAlgorithm, PsaSoftwareBackend, PsaSoftwareProvider,
};

#[cfg(feature = "provider-psa")]
pub use protocol::PsaExternalKeyProvider;
