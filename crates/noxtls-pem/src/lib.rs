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

//! PEM encoding and decoding helpers for certificates, keys, and generic DER payloads.
//!
//! Supports `no_std` builds with `alloc` and optional `std` helpers for filesystem I/O.

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod internal_alloc;

#[cfg(not(feature = "std"))]
use crate::internal_alloc::ToOwned;
use crate::internal_alloc::{String, Vec};
use noxtls_core::{Error, Result};
#[cfg(feature = "std")]
use std::path::Path;

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PEM_LABEL_CERTIFICATE: &str = "CERTIFICATE";
const PEM_LABEL_RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";
const PEM_LABEL_RSA_PUBLIC_KEY: &str = "RSA PUBLIC KEY";
const PEM_LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";
const PEM_LABEL_EC_PRIVATE_KEY: &str = "EC PRIVATE KEY";
const PEM_LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";

/// Converts certificate DER bytes into PEM `CERTIFICATE` armor.
///
/// # Arguments
///
/// * `der`: Raw DER certificate bytes.
///
/// # Returns
///
/// PEM text using `CERTIFICATE` label.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_der_to_pem`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_certificate_der_to_pem(der: &[u8]) -> Result<String> {
    noxtls_der_to_pem(der, PEM_LABEL_CERTIFICATE)
}

/// Parses one PEM `CERTIFICATE` block into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM certificate text containing exactly one certificate block.
///
/// # Returns
///
/// Raw DER certificate bytes.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_certificate_pem_to_der(pem: &str) -> Result<Vec<u8>> {
    noxtls_pem_to_der(pem, PEM_LABEL_CERTIFICATE)
}

/// Parses all PEM `CERTIFICATE` blocks into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM text that may include certificate chains or mixed labels.
///
/// # Returns
///
/// DER certificate blocks for every `CERTIFICATE` marker in input order.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der_blocks`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_certificate_chain_pem_to_der_blocks(pem: &str) -> Result<Vec<Vec<u8>>> {
    noxtls_pem_to_der_blocks(pem, PEM_LABEL_CERTIFICATE)
}

/// Converts PKCS#1 RSA private-key DER bytes into PEM armor.
///
/// # Arguments
///
/// * `der`: DER bytes for `RSAPrivateKey`.
///
/// # Returns
///
/// PEM text using `RSA PRIVATE KEY` label.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_der_to_pem`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_rsa_private_key_der_to_pem_pkcs1(der: &[u8]) -> Result<String> {
    noxtls_der_to_pem(der, PEM_LABEL_RSA_PRIVATE_KEY)
}

/// Parses one PEM PKCS#1 RSA private-key block into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM text containing exactly one `RSA PRIVATE KEY` block.
///
/// # Returns
///
/// DER bytes for `RSAPrivateKey`.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_rsa_private_key_pem_to_der_pkcs1(pem: &str) -> Result<Vec<u8>> {
    noxtls_pem_to_der(pem, PEM_LABEL_RSA_PRIVATE_KEY)
}

/// Converts PKCS#1 RSA public-key DER bytes into PEM armor.
///
/// # Arguments
///
/// * `der`: DER bytes for `RSAPublicKey`.
///
/// # Returns
///
/// PEM text using `RSA PUBLIC KEY` label.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_der_to_pem`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_rsa_public_key_der_to_pem_pkcs1(der: &[u8]) -> Result<String> {
    noxtls_der_to_pem(der, PEM_LABEL_RSA_PUBLIC_KEY)
}

/// Parses one PEM PKCS#1 RSA public-key block into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM text containing exactly one `RSA PUBLIC KEY` block.
///
/// # Returns
/// DER bytes for `RSAPublicKey`.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_rsa_public_key_pem_to_der_pkcs1(pem: &str) -> Result<Vec<u8>> {
    noxtls_pem_to_der(pem, PEM_LABEL_RSA_PUBLIC_KEY)
}

/// Converts PKCS#8 private-key DER bytes into PEM armor.
///
/// # Arguments
///
/// * `der`: DER bytes for `PrivateKeyInfo`.
///
/// # Returns
/// PEM text using `PRIVATE KEY` label.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_der_to_pem`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_private_key_der_to_pem_pkcs8(der: &[u8]) -> Result<String> {
    noxtls_der_to_pem(der, PEM_LABEL_PRIVATE_KEY)
}

/// Parses one PEM PKCS#8 private-key block into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM text containing exactly one `PRIVATE KEY` block.
///
/// # Returns
/// DER bytes for `PrivateKeyInfo`.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_private_key_pem_to_der_pkcs8(pem: &str) -> Result<Vec<u8>> {
    noxtls_pem_to_der(pem, PEM_LABEL_PRIVATE_KEY)
}

/// Converts SEC1 EC private-key DER bytes into PEM armor.
///
/// # Arguments
///
/// * `der`: DER bytes for SEC1 `ECPrivateKey`.
///
/// # Returns
/// PEM text using `EC PRIVATE KEY` label.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_der_to_pem`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_ec_private_key_der_to_pem_sec1(der: &[u8]) -> Result<String> {
    noxtls_der_to_pem(der, PEM_LABEL_EC_PRIVATE_KEY)
}

/// Parses one PEM SEC1 EC private-key block into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM text containing exactly one `EC PRIVATE KEY` block.
///
/// # Returns
///
/// DER bytes for SEC1 `ECPrivateKey`.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_ec_private_key_pem_to_der_sec1(pem: &str) -> Result<Vec<u8>> {
    noxtls_pem_to_der(pem, PEM_LABEL_EC_PRIVATE_KEY)
}

/// Converts SubjectPublicKeyInfo DER bytes into PEM armor.
///
/// # Arguments
///
/// * `der`: DER bytes for public key SPKI structure.
///
/// # Returns
/// PEM text using `PUBLIC KEY` label.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_der_to_pem`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_public_key_der_to_pem_spki(der: &[u8]) -> Result<String> {
    noxtls_der_to_pem(der, PEM_LABEL_PUBLIC_KEY)
}

/// Parses one PEM SPKI public-key block into DER bytes.
///
/// # Arguments
///
/// * `pem`: PEM text containing exactly one `PUBLIC KEY` block.
///
/// # Returns
/// DER bytes for subject public key info.
///
/// # Errors
///
/// Returns the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_public_key_pem_to_der_spki(pem: &str) -> Result<Vec<u8>> {
    noxtls_pem_to_der(pem, PEM_LABEL_PUBLIC_KEY)
}

/// Reads one PEM block from file and decodes DER payload for `label`.
///
/// # Arguments
///
/// * `path`: Filesystem path to a PEM file.
/// * `label`: Expected PEM label.
///
/// # Returns
///
/// DER bytes for exactly one matching PEM block.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] if the file cannot be read as UTF-8; otherwise the same errors as [`noxtls_pem_to_der`].
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn noxtls_pem_file_to_der(path: &Path, label: &str) -> Result<Vec<u8>> {
    let pem = std::fs::read_to_string(path)
        .map_err(|_| Error::ParseFailure("failed to read pem file"))?;
    noxtls_pem_to_der(&pem, label)
}

/// Reads all matching PEM blocks from file and decodes DER payloads for `label`.
///
/// # Arguments
///
/// * `path`: Filesystem path to a PEM file.
/// * `label`: Expected PEM label.
///
/// # Returns
/// DER bytes for each matching PEM block.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] if the file cannot be read, otherwise the same errors as [`noxtls_pem_to_der_blocks`].
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn noxtls_pem_file_to_der_blocks(path: &Path, label: &str) -> Result<Vec<Vec<u8>>> {
    let pem = std::fs::read_to_string(path)
        .map_err(|_| Error::ParseFailure("failed to read pem file"))?;
    noxtls_pem_to_der_blocks(&pem, label)
}

/// Encodes DER as PEM and writes it to a file path.
///
/// # Arguments
///
/// * `path`: Destination path for PEM text.
/// * `der`: DER bytes to encode.
/// * `label`: PEM label to apply.
///
/// # Returns
///
/// `Ok(())` after the PEM text is written to `path`.
///
/// # Errors
///
/// Returns errors from [`noxtls_der_to_pem`], or [`Error::ParseFailure`] if the file cannot be written.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn noxtls_der_to_pem_file(path: &Path, der: &[u8], label: &str) -> Result<()> {
    let pem = noxtls_der_to_pem(der, label)?;
    std::fs::write(path, pem).map_err(|_| Error::ParseFailure("failed to write pem file"))?;
    Ok(())
}

/// Writes raw DER bytes to a file path.
///
/// # Arguments
///
/// * `path`: Destination path for DER bytes.
/// * `der`: DER bytes to write.
///
/// # Returns
///
/// `Ok(())` on successful write.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] for empty `der`, or [`Error::ParseFailure`] if the file cannot be written.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn noxtls_der_to_file(path: &Path, der: &[u8]) -> Result<()> {
    if der.is_empty() {
        return Err(Error::InvalidLength("der input must not be empty"));
    }
    std::fs::write(path, der).map_err(|_| Error::ParseFailure("failed to write der file"))?;
    Ok(())
}

/// Converts DER bytes into PEM armor with caller-provided label.
///
/// # Arguments
///
/// * `der`: Raw DER bytes to encode.
/// * `label`: PEM label such as `CERTIFICATE` or `PUBLIC KEY`.
///
/// # Returns
///
/// UTF-8 PEM text including BEGIN/END markers and 64-column base64 lines.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `der` or `label` is empty, or [`Error::InvalidEncoding`] when `label` contains control characters.
///
/// # Panics
///
/// Panics if an internal `expect` on ASCII-only base64 chunk UTF-8 conversion fails (should be unreachable).
pub fn noxtls_der_to_pem(der: &[u8], label: &str) -> Result<String> {
    if der.is_empty() {
        return Err(Error::InvalidLength("der input must not be empty"));
    }
    if label.is_empty() {
        return Err(Error::InvalidLength("pem label must not be empty"));
    }
    if label.chars().any(char::is_control) {
        return Err(Error::InvalidEncoding(
            "pem label contains invalid control character",
        ));
    }
    let encoded = encode_base64(der);
    let mut pem = String::new();
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        let line =
            core::str::from_utf8(chunk).expect("base64 output is always valid ascii and utf-8");
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    Ok(pem)
}

/// Parses PEM armor into DER bytes and verifies expected label markers.
///
/// # Arguments
///
/// * `pem`: PEM text to parse.
/// * `label`: Expected PEM label, for example `CERTIFICATE`.
///
/// # Returns
///
/// Raw DER bytes extracted from the single matching PEM payload.
///
/// # Errors
///
/// Returns errors from [`noxtls_pem_to_der_blocks`], or [`Error::ParseFailure`] when zero or multiple blocks match `label`.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    let blocks = noxtls_pem_to_der_blocks(pem, label)?;
    if blocks.len() != 1 {
        return Err(Error::ParseFailure(
            "expected exactly one pem block for requested label",
        ));
    }
    Ok(blocks[0].clone())
}

/// Parses all PEM blocks matching `label` into DER payload bytes.
///
/// # Arguments
///
/// * `pem`: PEM text to scan.
/// * `label`: PEM label to collect, such as `CERTIFICATE`.
///
/// # Returns
///
/// Vector of DER payloads for each matching PEM block in input order.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] for empty `pem` or `label`, [`Error::InvalidEncoding`] for invalid labels or base64,
/// or [`Error::ParseFailure`] for malformed markers, nesting, mismatched begin/end, missing end, or no matching blocks.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_pem_to_der_blocks(pem: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    if pem.is_empty() {
        return Err(Error::InvalidLength("pem input must not be empty"));
    }
    if label.is_empty() {
        return Err(Error::InvalidLength("pem label must not be empty"));
    }
    if label.chars().any(char::is_control) {
        return Err(Error::InvalidEncoding(
            "pem label contains invalid control character",
        ));
    }

    let mut active_label: Option<String> = None;
    let mut payload = String::new();
    let mut out = Vec::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(begin_label) = parse_pem_marker_label(trimmed, "BEGIN ") {
            if active_label.is_some() {
                return Err(Error::ParseFailure("nested pem begin marker"));
            }
            active_label = Some(begin_label.to_owned());
            payload.clear();
            continue;
        }
        if let Some(end_label) = parse_pem_marker_label(trimmed, "END ") {
            let current_label = active_label
                .as_deref()
                .ok_or(Error::ParseFailure("pem end marker appears before begin"))?;
            if current_label != end_label {
                return Err(Error::ParseFailure("pem begin/end label mismatch"));
            }
            if current_label == label {
                if payload.is_empty() {
                    return Err(Error::InvalidEncoding("pem payload is empty"));
                }
                out.push(decode_base64(&payload)?);
            }
            active_label = None;
            payload.clear();
            continue;
        }
        if active_label.is_none() {
            continue;
        }
        payload.push_str(trimmed);
    }

    if active_label.is_some() {
        return Err(Error::ParseFailure("pem end marker missing"));
    }
    if out.is_empty() {
        return Err(Error::ParseFailure("pem begin/end markers not found"));
    }
    Ok(out)
}

/// Parses a PEM boundary line and returns the label between markers and `marker_kind`.
///
/// # Arguments
///
/// * `line` — Trimmed PEM line, for example `-----BEGIN CERTIFICATE-----`.
/// * `marker_kind` — Either `"BEGIN "` or `"END "` including trailing space.
///
/// # Returns
///
/// `Some(label)` when the line matches `-----{marker_kind}{label}-----`; otherwise `None`.
///
/// # Panics
///
/// This function does not panic.
fn parse_pem_marker_label<'a>(line: &'a str, marker_kind: &str) -> Option<&'a str> {
    let prefix = "-----";
    let suffix = "-----";
    if !line.starts_with(prefix) || !line.ends_with(suffix) {
        return None;
    }
    let inner = &line[prefix.len()..line.len() - suffix.len()];
    let label = inner.strip_prefix(marker_kind)?.trim();
    if label.is_empty() {
        return None;
    }
    Some(label)
}

/// Encodes `input` into RFC 4648 base64 alphabet text without line breaks.
///
/// # Arguments
///
/// * `input` — Raw bytes to encode (any length).
///
/// # Returns
///
/// A `String` of only base64 alphabet characters (no newlines).
///
/// # Panics
///
/// This function does not panic.
fn encode_base64(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut idx = 0_usize;
    while idx + 3 <= input.len() {
        let n = (u32::from(input[idx]) << 16)
            | (u32::from(input[idx + 1]) << 8)
            | u32::from(input[idx + 2]);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[(n & 0x3F) as usize] as char);
        idx += 3;
    }

    let rem = input.len() - idx;
    if rem == 1 {
        let n = u32::from(input[idx]) << 16;
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = (u32::from(input[idx]) << 16) | (u32::from(input[idx + 1]) << 8);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

/// Decodes strict RFC 4648 base64 payload text (with optional padding) into raw bytes.
///
/// # Arguments
///
/// * `input` — Concatenated base64 payload characters from PEM body lines.
///
/// # Returns
///
/// On success, decoded bytes whose length respects padding rules.
///
/// # Errors
///
/// Returns [`Error::InvalidEncoding`] for invalid length, padding order, or character set violations.
///
/// # Panics
///
/// This function does not panic.
fn decode_base64(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return Err(Error::InvalidEncoding(
            "pem base64 length must be divisible by 4",
        ));
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);

    for (chunk_idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = chunk_idx + 1 == bytes.len() / 4;
        let mut sextets = [0_u8; 4];
        let mut pad_count = 0_u8;
        for (i, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                sextets[i] = 0;
                pad_count = pad_count.saturating_add(1);
                continue;
            }
            if pad_count != 0 {
                return Err(Error::InvalidEncoding("invalid base64 padding order"));
            }
            sextets[i] = decode_base64_sextet(*byte)?;
        }
        if pad_count > 2 {
            return Err(Error::InvalidEncoding("invalid base64 padding width"));
        }
        if !is_last && pad_count != 0 {
            return Err(Error::InvalidEncoding(
                "base64 padding only allowed in final quartet",
            ));
        }

        let n = (u32::from(sextets[0]) << 18)
            | (u32::from(sextets[1]) << 12)
            | (u32::from(sextets[2]) << 6)
            | u32::from(sextets[3]);
        out.push(((n >> 16) & 0xFF) as u8);
        if pad_count < 2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if pad_count == 0 {
            out.push((n & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Maps one ASCII base64 character to its 6-bit sextet value.
///
/// # Arguments
///
/// * `byte` — Single ASCII code unit from a base64 quartet.
///
/// # Returns
///
/// On success, the decoded 6-bit value in `0..=63`.
///
/// # Errors
///
/// Returns [`Error::InvalidEncoding`] when `byte` is not in the base64 alphabet.
///
/// # Panics
///
/// This function does not panic.
fn decode_base64_sextet(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(26 + (byte - b'a')),
        b'0'..=b'9' => Ok(52 + (byte - b'0')),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Error::InvalidEncoding(
            "invalid base64 character in pem payload",
        )),
    }
}
