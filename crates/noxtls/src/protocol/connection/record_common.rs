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

//! Shared TLS record-packet helpers for TLS 1.2 and TLS 1.3 flows.

use super::*;

impl Connection {
    /// Parses TLS 1.2 alert payload bytes into level/description enums.
    ///
    /// # Arguments
    ///
    /// * `self` — `Connection` providing context for record handling.
    /// * `content_type` — Decoded record content type expected to be `Alert`.
    /// * `payload` — Alert payload bytes that must contain exactly two octets.
    ///
    /// # Returns
    ///
    /// On success, the parsed `(AlertLevel, AlertDescription)` pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParseFailure`] when content type is not alert, payload length is invalid, or alert values are unknown.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_parse_tls12_alert_payload(
        &self,
        content_type: RecordContentType,
        payload: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        if content_type != RecordContentType::Alert {
            return Err(Error::ParseFailure("record is not an alert content type"));
        }
        if payload.len() != 2 {
            return Err(Error::ParseFailure("tls12 alert payload must be two bytes"));
        }
        let level =
            AlertLevel::from_u8(payload[0]).ok_or(Error::ParseFailure("unknown alert level"))?;
        let description = AlertDescription::from_u8(payload[1])
            .ok_or(Error::ParseFailure("unknown alert description"))?;
        Ok((level, description))
    }

    /// Builds TLS 1.2 AEAD additional authenticated data per record sequence and header fields.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `sequence` — `sequence: u64`.
    /// * `content_type` — `content_type: RecordContentType`.
    /// * `plaintext_len` — `plaintext_len: usize`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_build_tls12_record_aad(
        &self,
        sequence: u64,
        content_type: RecordContentType,
        plaintext_len: usize,
    ) -> Result<[u8; 13]> {
        let len = u16::try_from(plaintext_len)
            .map_err(|_| Error::InvalidLength("tls12 plaintext length exceeds 16-bit field"))?;
        let mut aad = [0_u8; 13];
        aad[..8].copy_from_slice(&sequence.to_be_bytes());
        aad[8] = content_type.to_u8();
        aad[9..11].copy_from_slice(&noxtls_legacy_wire_version(self.version));
        aad[11..13].copy_from_slice(&len.to_be_bytes());
        Ok(aad)
    }

    /// Builds TLS 1.3 AEAD additional authenticated data from TLSCiphertext header fields.
    ///
    /// # Arguments
    ///
    /// * `payload_len` — TLSCiphertext encrypted record payload length (`ciphertext || tag`) in bytes.
    ///
    /// # Returns
    ///
    /// 5-byte TLS 1.3 AAD array `(content_type, legacy_version, length)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `payload_len` exceeds `u16::MAX`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_build_tls13_record_aad(&self, payload_len: usize) -> Result<[u8; 5]> {
        let len = u16::try_from(payload_len)
            .map_err(|_| Error::InvalidLength("tls13 record payload length exceeds u16 range"))?;
        let mut aad = [0_u8; 5];
        aad[0] = RecordContentType::ApplicationData.to_u8();
        aad[1..3].copy_from_slice(&0x0303_u16.to_be_bytes());
        aad[3..5].copy_from_slice(&len.to_be_bytes());
        Ok(aad)
    }

    /// Encodes protected payload into TLS 1.2 wire packet with version and content type.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `record` — `record: &ProtectedRecord`.
    /// * `content_type` — `content_type: RecordContentType`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_encode_tls12_record_packet(
        &self,
        record: &ProtectedRecord,
        content_type: RecordContentType,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(record.ciphertext.len() + record.tag.len());
        payload.extend_from_slice(&record.ciphertext);
        payload.extend_from_slice(&record.tag);
        noxtls_encode_tls12_ciphertext_record(
            content_type.to_u8(),
            noxtls_legacy_wire_version(self.version),
            &payload,
        )
    }

    /// Decodes TLS 1.2 wire packet into protected payload at one sequence number.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
    /// * `sequence` — `sequence: u64`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_decode_tls12_record_packet(
        &self,
        packet: &[u8],
        sequence: u64,
    ) -> Result<(ProtectedRecord, RecordContentType)> {
        let (content_type_u8, version, payload) = noxtls_decode_tls12_ciphertext_record(packet)?;
        let strict_version = noxtls_legacy_wire_version(self.version);
        let legacy_compat_ok = self.tls12_allow_legacy_record_versions
            && (version == [0x03, 0x01] || version == [0x03, 0x02]);
        if version != strict_version && !legacy_compat_ok {
            return Err(Error::ParseFailure(
                "tls12 record has invalid legacy version",
            ));
        }
        let content_type = RecordContentType::from_u8(content_type_u8)
            .ok_or(Error::ParseFailure("unknown tls12 record content type"))?;
        if payload.len() < 16 {
            return Err(Error::ParseFailure("tls12 record payload too short"));
        }
        let tag_offset = payload.len() - 16;
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(&payload[tag_offset..]);
        Ok((
            ProtectedRecord {
                sequence,
                ciphertext: payload[..tag_offset].to_vec(),
                tag,
            },
            content_type,
        ))
    }

    /// Encodes one protected record into TLS 1.3 TLSCiphertext wire format.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `record` — `record: &ProtectedRecord`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_encode_tls13_record_packet(&self, record: &ProtectedRecord) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(record.ciphertext.len() + record.tag.len());
        payload.extend_from_slice(&record.ciphertext);
        payload.extend_from_slice(&record.tag);
        noxtls_encode_tls13_ciphertext_record(&payload)
    }

    /// Decodes one TLS 1.3 TLSCiphertext packet into a protected record at one sequence.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
    /// * `sequence` — `sequence: u64`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_decode_tls13_record_packet(
        &self,
        packet: &[u8],
        sequence: u64,
    ) -> Result<ProtectedRecord> {
        let payload = noxtls_decode_tls13_ciphertext_record(packet)?;
        let tag_offset = payload.len() - 16;
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(&payload[tag_offset..]);
        Ok(ProtectedRecord {
            sequence,
            ciphertext: payload[..tag_offset].to_vec(),
            tag,
        })
    }

    /// Ensures TLS1.2 wire-packet APIs are used only on TLS 1.0/1.1/1.2 connections.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_ensure_tls12_wire_mode(&self) -> Result<()> {
        if self.version == TlsVersion::Tls10
            || self.version == TlsVersion::Tls11
            || self.version == TlsVersion::Tls12
        {
            return Ok(());
        }
        Err(Error::StateError(
            "tls12 record packets require TLS 1.0/1.1/1.2 connection",
        ))
    }
}
