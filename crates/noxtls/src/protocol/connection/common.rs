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

//! Shared helpers used across TLS/DTLS connection submodules.

use super::*;

impl Connection {
    /// Sets maximum accepted record plaintext length for seal/open operations.
    ///
    /// # Arguments
    /// * `max_len`: Plaintext limit in bytes (must be in `1..=16384`).
    ///
    /// # Returns
    /// `Ok(())` when the limit is accepted.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_set_max_record_plaintext_len(&mut self, max_len: usize) -> Result<()> {
        if max_len == 0 || max_len > TLS_MAX_RECORD_PLAINTEXT_LEN {
            return Err(Error::InvalidLength(
                "record plaintext limit must be between 1 and 16384 bytes",
            ));
        }
        self.max_record_plaintext_len = max_len;
        Ok(())
    }

    /// Computes the current transcript hash bytes for post-handshake key schedule use.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Current transcript hash bytes from selected hash noxtls_algorithm.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_transcript_hash(&self) -> Vec<u8> {
        self.noxtls_transcript_hash.noxtls_snapshot_hash()
    }

    /// Returns currently negotiated cipher suite, if known from ServerHello.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Selected cipher suite when negotiation has completed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_selected_cipher_suite(&self) -> Option<CipherSuite> {
        self.noxtls_selected_cipher_suite
    }

    /// Computes version-appropriate expected **peer** Finished `verify_data` bytes.
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
    pub fn noxtls_compute_expected_finished(&self) -> Result<Vec<u8>> {
        let hash = self.noxtls_transcript_hash();
        match self.version {
            TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                let secret = self.handshake_secret.as_ref().ok_or(Error::StateError(
                    "handshake secret must be available before finished",
                ))?;
                noxtls_tls12_prf_for_hash(
                    self.noxtls_negotiated_hash_algorithm(),
                    secret,
                    b"client finished",
                    &hash,
                    12,
                )
            }
            TlsVersion::Tls13 | TlsVersion::Dtls13 => {
                let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
                let hash_len = noxtls_hash_algorithm.output_len();
                let peer_hs = if self.tls_role == TlsRole::Server {
                    self.tls13_client_handshake_traffic_secret
                        .as_ref()
                        .ok_or(Error::StateError(
                            "tls13 client handshake traffic secret must be installed before finished verify",
                        ))?
                } else {
                    self.tls13_server_handshake_traffic_secret
                        .as_ref()
                        .ok_or(Error::StateError(
                            "tls13 server handshake traffic secret must be installed before finished verify",
                        ))?
                };
                let finished_key = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    peer_hs,
                    b"finished",
                    &[],
                    hash_len,
                )?;
                Ok(noxtls_finished_hmac_for_hash(
                    noxtls_hash_algorithm,
                    &finished_key,
                    &hash,
                ))
            }
            TlsVersion::Tls10 | TlsVersion::Tls11 => Ok(noxtls_finished_hmac_for_hash(
                self.noxtls_negotiated_hash_algorithm(),
                b"finished",
                &hash,
            )),
        }
    }

    /// Computes expected client Finished verify data for TLS 1.3 server-role connections.
    ///
    /// # Arguments
    ///
    /// * `&self` — Server connection with client handshake traffic secret installed.
    ///
    /// # Returns
    ///
    /// On success, expected client `verify_data` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when TLS 1.3 handshake traffic secrets are unavailable.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_compute_expected_client_finished(&self) -> Result<Vec<u8>> {
        self.noxtls_compute_expected_finished()
    }

    /// Appends bytes to transcript log and selected transcript hash context.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `message` — `message: &[u8]`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_append_transcript(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
        self.noxtls_transcript_hash.noxtls_update(message);
    }

    /// Resets transcript bytes/hash for a noxtls_new handshake flight from `Idle`.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_reset_transcript_for_new_handshake(&mut self) {
        self.transcript.clear();
        self.noxtls_transcript_hash = TranscriptHashState::noxtls_for_version(self.version);
    }

    /// Rebuilds transcript hash context from stored transcript bytes and selected suite policy.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_rebuild_transcript_hash_from_selected_suite(&mut self) {
        let Some(suite) = self.noxtls_selected_cipher_suite else {
            return;
        };
        self.noxtls_transcript_hash = suite.noxtls_transcript_hash_state();
        self.noxtls_transcript_hash.noxtls_update(&self.transcript);
    }

    /// Applies TLS 1.3 HRR transcript reset via synthetic message_hash entry.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_reset_transcript_for_hrr(&mut self) {
        let prior_hash = self.noxtls_transcript_hash();
        self.transcript.clear();
        if let Some(suite) = self.noxtls_selected_cipher_suite {
            self.noxtls_transcript_hash = suite.noxtls_transcript_hash_state();
        } else {
            self.noxtls_transcript_hash = TranscriptHashState::noxtls_for_version(self.version);
        }
        let message_hash = noxtls_encode_handshake_message(0xFE, &prior_hash);
        self.noxtls_append_transcript(&message_hash);
    }
}

/// Compares byte slices in constant-time style and returns equality result.
///
/// # Arguments
///
/// * `left` — `left: &[u8]`.
/// * `right` — `right: &[u8]`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
pub(super) fn noxtls_constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max_len {
        let l = left.get(idx).copied().unwrap_or(0);
        let r = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
}
