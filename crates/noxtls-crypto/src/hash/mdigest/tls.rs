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

use super::{hmac_sha256, hmac_sha384, sha256, sha384, Digest, Sha256};

/// Tracks TLS handshake transcript using streaming SHA-256 updates.
#[derive(Debug, Clone, Default)]
pub struct TlsTranscriptSha256 {
    hasher: Sha256,
}

impl TlsTranscriptSha256 {
    /// Creates a new transcript hasher with an empty transcript state.
    ///
    /// # Returns
    /// Fresh SHA-256 transcript accumulator.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one handshake message to the transcript hash context.
    ///
    /// # Arguments
    /// * `self` — Running transcript hasher.
    /// * `message` — Serialized TLS handshake message bytes to append.
    ///
    /// # Returns
    ///
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    /// Returns a snapshot hash of the transcript without consuming state.
    ///
    /// # Arguments
    ///
    /// * `self` — Transcript state to clone for hashing.
    ///
    /// # Returns
    /// Current transcript hash as 32-byte SHA-256 digest.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn snapshot_hash(&self) -> [u8; 32] {
        let digest = self.hasher.clone().finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

/// Tracks TLS handshake transcript using buffered SHA-384 snapshots.
#[derive(Debug, Clone, Default)]
pub struct TlsTranscriptSha384 {
    transcript: Vec<u8>,
}

impl TlsTranscriptSha384 {
    /// Creates a new SHA-384 transcript hasher with an empty transcript state.
    ///
    /// # Returns
    /// Fresh SHA-384 transcript accumulator.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one handshake message to the transcript buffer.
    ///
    /// # Arguments
    /// * `self` — Running transcript buffer.
    /// * `message` — Serialized TLS handshake message bytes to append.
    ///
    /// # Returns
    ///
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn update(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }

    /// Returns a snapshot hash of the transcript without consuming state.
    ///
    /// # Arguments
    ///
    /// * `self` — Buffered transcript bytes to hash.
    ///
    /// # Returns
    /// Current transcript hash as 48-byte SHA-384 digest.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn snapshot_hash(&self) -> [u8; 48] {
        sha384(&self.transcript)
    }
}

/// Computes TLS 1.2 PRF output using SHA-256 and the requested output length.
///
/// # Arguments
/// * `secret`: PRF secret input (typically master secret).
/// * `label`: TLS PRF label bytes.
/// * `seed`: Additional seed material (for example transcript-derived values).
/// * `len`: Number of output bytes to derive.
///
/// # Returns
/// Derived PRF output with length `len`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `secret` is empty.
///
/// # Panics
///
/// This function does not panic.
pub fn tls12_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Result<Vec<u8>> {
    if secret.is_empty() {
        return Err(Error::InvalidLength("tls12 prf secret must not be empty"));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = hmac_sha256(secret, &label_seed);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut block_input = Vec::with_capacity(a.len() + label_seed.len());
        block_input.extend_from_slice(&a);
        block_input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_sha256(secret, &block_input));
        a = hmac_sha256(secret, &a);
    }
    out.truncate(len);
    Ok(out)
}

/// Computes TLS 1.2 PRF output using SHA-384 and the requested output length.
///
/// # Arguments
/// * `secret`: PRF secret input (typically master secret).
/// * `label`: TLS PRF label bytes.
/// * `seed`: Additional seed material.
/// * `len`: Number of output bytes to derive.
///
/// # Returns
/// Derived PRF output with length `len`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `secret` is empty.
///
/// # Panics
///
/// This function does not panic.
pub fn tls12_prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Result<Vec<u8>> {
    if secret.is_empty() {
        return Err(Error::InvalidLength("tls12 prf secret must not be empty"));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = hmac_sha384(secret, &label_seed);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut block_input = Vec::with_capacity(a.len() + label_seed.len());
        block_input.extend_from_slice(&a);
        block_input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_sha384(secret, &block_input));
        a = hmac_sha384(secret, &a);
    }
    out.truncate(len);
    Ok(out)
}

/// Computes TLS 1.2 verify_data for Finished using SHA-256 transcript hash.
///
/// # Arguments
/// * `master_secret`: TLS master secret bytes.
/// * `finished_label`: Finished label (`client finished` or `server finished`).
/// * `transcript`: Serialized handshake transcript bytes.
///
/// # Returns
/// 12-byte `verify_data` output for TLS 1.2 Finished.
///
/// # Errors
///
/// Forwards errors from [`tls12_prf_sha256`] (for example empty `master_secret`).
///
/// # Panics
///
/// This function does not panic.
pub fn tls12_finished_verify_data_sha256(
    master_secret: &[u8],
    finished_label: &[u8],
    transcript: &[u8],
) -> Result<[u8; 12]> {
    let hash = sha256(transcript);
    let verify = tls12_prf_sha256(master_secret, finished_label, &hash, 12)?;
    let mut out = [0_u8; 12];
    out.copy_from_slice(&verify);
    Ok(out)
}

/// Computes TLS 1.2 verify_data for Finished using SHA-384 transcript hash.
///
/// # Arguments
/// * `master_secret`: TLS master secret bytes.
/// * `finished_label`: Finished label (`client finished` or `server finished`).
/// * `transcript`: Serialized handshake transcript bytes.
///
/// # Returns
/// 12-byte `verify_data` output for TLS 1.2 Finished.
///
/// # Errors
///
/// Forwards errors from [`tls12_prf_sha384`] (for example empty `master_secret`).
///
/// # Panics
///
/// This function does not panic.
pub fn tls12_finished_verify_data_sha384(
    master_secret: &[u8],
    finished_label: &[u8],
    transcript: &[u8],
) -> Result<[u8; 12]> {
    let hash = sha384(transcript);
    let verify = tls12_prf_sha384(master_secret, finished_label, &hash, 12)?;
    let mut out = [0_u8; 12];
    out.copy_from_slice(&verify);
    Ok(out)
}
