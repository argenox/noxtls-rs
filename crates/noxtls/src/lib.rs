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
    derive_deterministic_p256_private, derive_deterministic_x25519_private,
    derive_tls13_p256_shared_secret, derive_tls13_x25519_shared_secret,
    dtls13_aes128gcm_record_size, encode_dtls_record_header, encode_dtls_record_packet,
    hkdf_extract_for_hash, hkdf_extract_with_salt_for_hash, open_dtls13_aes128gcm_record,
    parse_dtls12_handshake_fragment, parse_dtls_record_header, parse_dtls_record_packet,
    reassemble_dtls12_handshake_fragments, seal_dtls13_aes128gcm_record,
    tls13_client_hello_offers_supported_key_exchange, tls13_expand_label_for_hash,
    tls13_key_share_group_supported, tls13_signature_algorithm_supported, AlertDescription,
    AlertLevel, CipherSuite, ClientHelloExtensions, ClientHelloInfo, Connection,
    DtlsEpochReplayTracker, DtlsFlightRecord, DtlsFlightRetransmitTracker, DtlsOperationalPolicy,
    DtlsOperationalProfile, DtlsRecordHeader, DtlsReplayWindow, ExternalKeyHandle,
    ExternalKeyProvider, HandshakeState, HashAlgorithm, KeyDecryptAlgorithm, KeyDecryptRequest,
    KeyDeriveAlgorithm, KeyDeriveRequest, KeySignAlgorithm, KeySignRequest, ProtectedRecord,
    RecordContentType, ResumptionTicket, SoftwareKeyProvider, TicketStore, TicketUsagePolicy,
    Tls13EarlyDataOperationalPolicy, Tls13EarlyDataOperationalProfile, Tls13EarlyDataReplayState,
    Tls13EarlyDataTelemetry, Tls13OcspStapleVerification, Tls13OcspStapleVerifier,
    Tls13QuicInitialSecrets, Tls13QuicNextTrafficSecrets, Tls13QuicPacketProtectionKeys,
    Tls13QuicTrafficSecretSnapshot, TlsVersion, TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT,
    TLS13_QUIC_EXPORTER_LABEL_SERVER_1RTT,
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
