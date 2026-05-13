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

use super::{noxtls_hmac_sha256, noxtls_hmac_sha384};

/// Extracts a pseudorandom key (PRK) using HKDF-Extract with SHA-256.
///
/// # Arguments
/// * `salt`: Optional salt value; an all-zero 32-byte salt is used when empty.
/// * `ikm`: Input keying material to extract from.
///
/// # Returns
/// A 32-byte pseudorandom key suitable for HKDF expand steps.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let effective_salt = if salt.is_empty() {
        &[0_u8; 32][..]
    } else {
        salt
    };
    noxtls_hmac_sha256(effective_salt, ikm)
}

/// Expands HKDF output material using SHA-256 and requested output length.
///
/// # Arguments
/// * `prk`: Pseudorandom key produced by HKDF-Extract (must be at least 32 bytes).
/// * `info`: Optional context/application-specific info string.
/// * `len`: Number of output bytes to derive (max `255 * 32`).
///
/// # Returns
/// Derived output keying material with exact requested length.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `prk` is shorter than 32 bytes or `len` exceeds `255 * 32`.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if prk.len() < 32 {
        return Err(Error::InvalidLength("hkdf prk must be at least 32 bytes"));
    }
    if len > 32 * 255 {
        return Err(Error::InvalidLength("hkdf output length exceeds RFC limit"));
    }
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::new();
    let n = len.div_ceil(32);
    for idx in 1..=n {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(idx as u8);
        t = noxtls_hmac_sha256(prk, &msg).to_vec();
        okm.extend_from_slice(&t);
    }
    okm.truncate(len);
    Ok(okm)
}

/// Extracts a pseudorandom key (PRK) using HKDF-Extract with SHA-384.
///
/// # Arguments
/// * `salt`: Optional salt value; an all-zero 48-byte salt is used when empty.
/// * `ikm`: Input keying material to extract from.
///
/// # Returns
/// A 48-byte pseudorandom key suitable for HKDF expand steps.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let effective_salt = if salt.is_empty() {
        &[0_u8; 48][..]
    } else {
        salt
    };
    noxtls_hmac_sha384(effective_salt, ikm)
}

/// Expands HKDF output material using SHA-384 and requested output length.
///
/// # Arguments
/// * `prk`: Pseudorandom key produced by HKDF-Extract (must be at least 48 bytes).
/// * `info`: Optional context/application-specific info string.
/// * `len`: Number of output bytes to derive (max `255 * 48`).
///
/// # Returns
/// Derived output keying material with exact requested length.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `prk` is shorter than 48 bytes or `len` exceeds `255 * 48`.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_hkdf_expand_sha384(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if prk.len() < 48 {
        return Err(Error::InvalidLength("hkdf prk must be at least 48 bytes"));
    }
    if len > 48 * 255 {
        return Err(Error::InvalidLength("hkdf output length exceeds RFC limit"));
    }
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::new();
    let n = len.div_ceil(48);
    for idx in 1..=n {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(idx as u8);
        t = noxtls_hmac_sha384(prk, &msg).to_vec();
        okm.extend_from_slice(&t);
    }
    okm.truncate(len);
    Ok(okm)
}
