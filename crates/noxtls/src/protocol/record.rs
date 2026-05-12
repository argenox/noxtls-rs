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

use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

const TLS13_OUTER_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const TLS13_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const TLS13_AEAD_TAG_LEN: usize = 16;
const TLS13_MIN_CIPHERTEXT_LEN: usize = 1 + TLS13_AEAD_TAG_LEN;
const TLS12_RECORD_HEADER_LEN: usize = 5;

/// Builds a TLS AEAD record nonce by XORing the static IV with the sequence number in the low eight bytes.
///
/// # Arguments
///
/// * `base_iv` — 12-byte write IV or read IV for the epoch.
/// * `sequence` — Record sequence number combined into the nonce tail.
///
/// # Returns
///
/// A 12-byte nonce suitable for AES-GCM / ChaCha20-Poly1305 in TLS 1.3 style.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_record_nonce(base_iv: &[u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = *base_iv;
    let seq_bytes = sequence.to_be_bytes();
    for (idx, byte) in seq_bytes.iter().enumerate() {
        nonce[4 + idx] ^= *byte;
    }
    nonce
}

/// Encodes TLS 1.3 `TLSInnerPlaintext` as `content || content_type ||` zero padding.
///
/// # Arguments
///
/// * `content` — Inner plaintext bytes before the trailing type byte.
/// * `content_type` — `ContentType` value stored after the content.
/// * `padding_len` — Number of zero bytes appended after the type byte.
///
/// # Returns
///
/// Owned buffer holding the inner plaintext encoding.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn encode_tls13_inner_plaintext(
    content: &[u8],
    content_type: u8,
    padding_len: usize,
) -> Vec<u8> {
    let mut inner = Vec::with_capacity(content.len() + 1 + padding_len);
    inner.extend_from_slice(content);
    inner.push(content_type);
    inner.resize(inner.len() + padding_len, 0x00);
    inner
}

/// Decodes TLS 1.3 `TLSInnerPlaintext` by stripping zero padding and splitting content from type.
///
/// # Arguments
///
/// * `inner` — Decrypted inner plaintext bytes.
///
/// # Returns
///
/// On success, `(content, content_type)` where `content` is owned.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when the buffer is empty or contains only padding without a type byte.
///
/// # Panics
///
/// This function does not panic.
pub fn decode_tls13_inner_plaintext(inner: &[u8]) -> Result<(Vec<u8>, u8)> {
    if inner.is_empty() {
        return Err(Error::ParseFailure(
            "tls13 inner plaintext must not be empty",
        ));
    }
    let mut idx = inner.len();
    while idx > 0 && inner[idx - 1] == 0x00 {
        idx -= 1;
    }
    if idx == 0 {
        return Err(Error::ParseFailure(
            "tls13 inner plaintext missing content type",
        ));
    }
    let content_type = inner[idx - 1];
    let content = inner[..idx - 1].to_vec();
    Ok((content, content_type))
}

/// Encodes TLS 1.3 `TLSCiphertext` wire bytes as `type || legacy_version || length || payload`.
///
/// # Arguments
///
/// * `payload` — Ciphertext including the final authentication tag for AEAD modes.
///
/// # Returns
///
/// On success, owned record bytes including the five-byte header.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when the payload is shorter than the minimum AEAD ciphertext size or longer than `u16::MAX`.
///
/// # Panics
///
/// This function does not panic.
pub fn encode_tls13_ciphertext_record(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < TLS13_MIN_CIPHERTEXT_LEN {
        return Err(Error::InvalidLength(
            "tls13 ciphertext payload is too short",
        ));
    }
    if payload.len() > usize::from(u16::MAX) {
        return Err(Error::InvalidLength(
            "tls13 ciphertext payload is too large",
        ));
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(TLS13_OUTER_CONTENT_TYPE_APPLICATION_DATA);
    out.extend_from_slice(&TLS13_LEGACY_RECORD_VERSION);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parses TLS 1.3 `TLSCiphertext` framing and returns the authenticated payload bytes.
///
/// # Arguments
///
/// * `packet` — Full record bytes including header and payload.
///
/// # Returns
///
/// On success, owned ciphertext payload (including AEAD tag octets).
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when the header is truncated, outer type or legacy version mismatches, length is inconsistent, or trailing bytes remain.
///
/// # Panics
///
/// This function does not panic.
pub fn decode_tls13_ciphertext_record(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < 5 {
        return Err(Error::ParseFailure("tls13 record header truncated"));
    }
    if packet[0] != TLS13_OUTER_CONTENT_TYPE_APPLICATION_DATA {
        return Err(Error::ParseFailure(
            "tls13 record has invalid outer content type",
        ));
    }
    if packet[1..3] != TLS13_LEGACY_RECORD_VERSION {
        return Err(Error::ParseFailure(
            "tls13 record has invalid legacy version",
        ));
    }
    let payload_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    let payload_start = 5;
    let payload_end = payload_start + payload_len;
    if payload_end > packet.len() {
        return Err(Error::ParseFailure("tls13 record payload truncated"));
    }
    if payload_end != packet.len() {
        return Err(Error::ParseFailure("tls13 record has trailing bytes"));
    }
    if payload_len < TLS13_MIN_CIPHERTEXT_LEN {
        return Err(Error::ParseFailure("tls13 record payload too short"));
    }
    Ok(packet[payload_start..payload_end].to_vec())
}

/// Encodes a TLS 1.2-style ciphertext record as `type || version || length || payload`.
///
/// # Arguments
///
/// * `content_type` — Record-layer content type byte.
/// * `version` — Legacy record version field (two bytes).
/// * `payload` — Ciphertext payload bytes.
///
/// # Returns
///
/// On success, owned record bytes including the five-byte header.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `payload` exceeds `u16::MAX` bytes.
///
/// # Panics
///
/// This function does not panic.
pub fn encode_tls12_ciphertext_record(
    content_type: u8,
    version: [u8; 2],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > usize::from(u16::MAX) {
        return Err(Error::InvalidLength(
            "tls12 ciphertext payload is too large",
        ));
    }
    let mut out = Vec::with_capacity(TLS12_RECORD_HEADER_LEN + payload.len());
    out.push(content_type);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parses a TLS 1.2-style ciphertext record and returns content type, version, and payload.
///
/// # Arguments
///
/// * `packet` — Full record bytes including header and payload.
///
/// # Returns
///
/// On success, `(content_type, version, payload)` where `payload` is owned.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when the header is truncated, declared length overflows the buffer, or trailing bytes remain.
///
/// # Panics
///
/// This function does not panic.
pub fn decode_tls12_ciphertext_record(packet: &[u8]) -> Result<(u8, [u8; 2], Vec<u8>)> {
    if packet.len() < TLS12_RECORD_HEADER_LEN {
        return Err(Error::ParseFailure("tls12 record header truncated"));
    }
    let content_type = packet[0];
    let version = [packet[1], packet[2]];
    let payload_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    let payload_start = TLS12_RECORD_HEADER_LEN;
    let payload_end = payload_start + payload_len;
    if payload_end > packet.len() {
        return Err(Error::ParseFailure("tls12 record payload truncated"));
    }
    if payload_end != packet.len() {
        return Err(Error::ParseFailure("tls12 record has trailing bytes"));
    }
    Ok((
        content_type,
        version,
        packet[payload_start..payload_end].to_vec(),
    ))
}
