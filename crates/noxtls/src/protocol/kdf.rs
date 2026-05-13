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
use noxtls_crypto::{
    noxtls_hkdf_expand_sha256, noxtls_hkdf_expand_sha384, noxtls_hkdf_extract_sha256, noxtls_hkdf_extract_sha384, noxtls_hmac_sha256,
    noxtls_hmac_sha384, noxtls_sha256, noxtls_sha384,
};

/// Identifies the hash algorithm selected by a cipher suite or version profile for HKDF and transcript work.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    /// Returns digest length in bytes for the selected hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `self` — Selected hash algorithm variant.
    ///
    /// # Returns
    ///
    /// `32` for SHA-256 and `48` for SHA-384 in this port.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// Extracts HKDF PRK using the selected hash algorithm and an all-zero salt of digest length.
///
/// # Arguments
///
/// * `hash_algorithm` — Hash backend used for HKDF-Extract.
/// * `ikm` — Input keying material supplied to HKDF-Extract.
///
/// # Returns
///
/// Owned PRK bytes of length `hash_algorithm.output_len()`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hkdf_extract_for_hash(hash_algorithm: HashAlgorithm, ikm: &[u8]) -> Vec<u8> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hkdf_extract_sha256(&[0_u8; 32], ikm).to_vec(),
        HashAlgorithm::Sha384 => noxtls_hkdf_extract_sha384(&[0_u8; 48], ikm).to_vec(),
    }
}

/// Extracts HKDF PRK using caller-provided salt for TLS 1.3 stage chaining.
///
/// # Arguments
///
/// * `hash_algorithm` — Hash backend used for HKDF-Extract.
/// * `salt` — Salt bytes; length should match the profile feeding this helper.
/// * `ikm` — Input keying material supplied to HKDF-Extract.
///
/// # Returns
///
/// Owned PRK bytes of length `hash_algorithm.output_len()`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hkdf_extract_with_salt_for_hash(
    hash_algorithm: HashAlgorithm,
    salt: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hkdf_extract_sha256(salt, ikm).to_vec(),
        HashAlgorithm::Sha384 => noxtls_hkdf_extract_sha384(salt, ikm).to_vec(),
    }
}

/// Expands HKDF key material using the selected hash algorithm.
///
/// # Arguments
///
/// * `hash_algorithm` — Hash backend used for HKDF-Expand.
/// * `prk` — Pseudorandom key from HKDF-Extract.
/// * `info` — HKDF info octets.
/// * `len` — Number of output bytes to expand.
///
/// # Returns
///
/// On success, `len` expanded octets.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the crypto backend rejects the expand request (for example invalid lengths).
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_hkdf_expand_for_hash(
    hash_algorithm: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hkdf_expand_sha256(prk, info, len),
        HashAlgorithm::Sha384 => noxtls_hkdf_expand_sha384(prk, info, len),
    }
}

/// Expands TLS 1.3 HKDF-Label structure bytes using the selected hash backend.
///
/// # Arguments
///
/// * `hash_algorithm` — Hash backend used for HKDF-Expand.
/// * `secret` — Secret input to HKDF-Expand (for example a handshake traffic secret).
/// * `label` — Label suffix appended after the `tls13 ` prefix inside the HKDF-Label string.
/// * `context` — Context octets embedded in the HKDF-Label.
/// * `len` — Number of output bytes to expand.
///
/// # Returns
///
/// On success, `len` expanded octets.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when the composed label or context exceeds `u8::MAX`, or other [`noxtls_core::Error`] values from HKDF expand.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_tls13_expand_label_for_hash(
    hash_algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(len as u16).to_be_bytes());
    let mut full_label = b"tls13 ".to_vec();
    full_label.extend_from_slice(label);
    if full_label.len() > u8::MAX as usize || context.len() > u8::MAX as usize {
        return Err(Error::InvalidLength("tls13 hkdf label/context too long"));
    }
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    noxtls_hkdf_expand_for_hash(hash_algorithm, secret, &hkdf_label, len)
}

/// Computes the TLS `verify_data` / Finished MAC output using the suite-selected transcript hash.
///
/// # Arguments
///
/// * `hash_algorithm` — HMAC digest algorithm matching the negotiated suite.
/// * `key` — Finished key material.
/// * `transcript_hash` — Transcript hash bytes input to HMAC.
///
/// # Returns
///
/// Owned MAC tag bytes of digest length.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_finished_hmac_for_hash(
    hash_algorithm: HashAlgorithm,
    key: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hmac_sha256(key, transcript_hash).to_vec(),
        HashAlgorithm::Sha384 => noxtls_hmac_sha384(key, transcript_hash).to_vec(),
    }
}

/// Hashes `input` with the hash algorithm used by the modeled key schedule.
///
/// # Arguments
///
/// * `hash_algorithm` — Digest algorithm to use.
/// * `input` — Message bytes to hash.
///
/// # Returns
///
/// Owned digest bytes of length `hash_algorithm.output_len()`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hash_bytes_for_algorithm(hash_algorithm: HashAlgorithm, input: &[u8]) -> Vec<u8> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_sha256(input).to_vec(),
        HashAlgorithm::Sha384 => noxtls_sha384(input).to_vec(),
    }
}
