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

/// Enumerates currently modeled TLS and DTLS protocol versions.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Dtls12,
    Dtls13,
}

impl TlsVersion {
    /// Returns `true` when this version uses TLS 1.3 handshake semantics (TLS 1.3 or DTLS 1.3).
    ///
    /// # Arguments
    ///
    /// * `self` — Protocol version under inspection.
    ///
    /// # Returns
    ///
    /// `true` for [`TlsVersion::Tls13`] and [`TlsVersion::Dtls13`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn uses_tls13_handshake_semantics(self) -> bool {
        matches!(self, Self::Tls13 | Self::Dtls13)
    }

    /// Returns `true` when this version is a DTLS datagram profile.
    ///
    /// # Arguments
    ///
    /// * `self` — Protocol version under inspection.
    ///
    /// # Returns
    ///
    /// `true` for [`TlsVersion::Dtls12`] and [`TlsVersion::Dtls13`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn is_dtls(self) -> bool {
        matches!(self, Self::Dtls12 | Self::Dtls13)
    }
}

/// Identifies whether a connection endpoint acts as TLS client or server.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TlsRole {
    Client,
    Server,
}

/// Represents coarse handshake phases used by the prototype state machine.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HandshakeState {
    Idle,
    /// Server received and accepted a ClientHello (server role only).
    ClientHelloReceived,
    /// Server transmitted ServerHello (server role only).
    ServerHelloSent,
    ClientHelloSent,
    ServerHelloReceived,
    ServerEncryptedExtensionsReceived,
    ServerCertificateRequestReceived,
    ServerCertificateReceived,
    ServerCertificateVerified,
    KeysDerived,
    Finished,
}

/// Identifies modeled cipher suites and their transcript hash algorithms.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    /// TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` (IANA `0x1303`).
    TlsChacha20Poly1305Sha256,
    TlsEcdheRsaWithAes128GcmSha256,
    TlsEcdheRsaWithAes256GcmSha384,
}

/// TLS record content types used by outer and inner TLS 1.3 framing.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecordContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl RecordContentType {
    /// Converts the content type to its wire byte value.
    ///
    /// # Arguments
    ///
    /// * `self` — Content type variant.
    ///
    /// # Returns
    ///
    /// The TLS `ContentType` octet for this variant.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Invalid => 0x00,
            Self::ChangeCipherSpec => 0x14,
            Self::Alert => 0x15,
            Self::Handshake => 0x16,
            Self::ApplicationData => 0x17,
        }
    }

    /// Parses a wire byte into a known content-type value.
    ///
    /// # Arguments
    ///
    /// * `value` — Raw `ContentType` byte from a record header.
    ///
    /// # Returns
    ///
    /// `Some` variant when `value` is recognized; otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Invalid),
            0x14 => Some(Self::ChangeCipherSpec),
            0x15 => Some(Self::Alert),
            0x16 => Some(Self::Handshake),
            0x17 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// TLS alert level codes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AlertLevel {
    Warning,
    Fatal,
}

impl AlertLevel {
    /// Converts an alert level into the wire byte value.
    ///
    /// # Arguments
    ///
    /// * `self` — Alert level variant.
    ///
    /// # Returns
    ///
    /// The TLS `AlertLevel` octet for this variant.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Warning => 1,
            Self::Fatal => 2,
        }
    }

    /// Parses a wire byte into a known alert level.
    ///
    /// # Arguments
    ///
    /// * `value` — Raw alert level byte.
    ///
    /// # Returns
    ///
    /// `Some` variant when `value` is `1` or `2`; otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Warning),
            2 => Some(Self::Fatal),
            _ => None,
        }
    }
}

/// TLS alert description codepoints used by this port.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AlertDescription {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    HandshakeFailure,
    CertificateUnknown,
    IllegalParameter,
    InternalError,
    UserCanceled,
}

impl AlertDescription {
    /// Converts an alert description into its wire byte value.
    ///
    /// # Arguments
    ///
    /// * `self` — Alert description variant.
    ///
    /// # Returns
    ///
    /// The TLS `AlertDescription` octet for this modeled subset.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::CloseNotify => 0,
            Self::UnexpectedMessage => 10,
            Self::BadRecordMac => 20,
            Self::HandshakeFailure => 40,
            Self::CertificateUnknown => 46,
            Self::IllegalParameter => 47,
            Self::InternalError => 80,
            Self::UserCanceled => 90,
        }
    }

    /// Parses a wire byte into a known alert description.
    ///
    /// # Arguments
    ///
    /// * `value` — Raw alert description byte.
    ///
    /// # Returns
    ///
    /// `Some` variant when `value` matches one of the modeled codepoints; otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CloseNotify),
            10 => Some(Self::UnexpectedMessage),
            20 => Some(Self::BadRecordMac),
            40 => Some(Self::HandshakeFailure),
            46 => Some(Self::CertificateUnknown),
            47 => Some(Self::IllegalParameter),
            80 => Some(Self::InternalError),
            90 => Some(Self::UserCanceled),
            _ => None,
        }
    }
}
