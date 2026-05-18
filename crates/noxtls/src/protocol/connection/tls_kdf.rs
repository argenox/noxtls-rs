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

//! TLS key-schedule and KDF helpers.

use super::*;

impl Connection {
    /// Computes Finished verify data for the active protocol version.
    ///
    /// # Arguments
    /// * `self` — Connection with transcript and handshake secrets populated.
    ///
    /// # Returns
    /// On success, the expected `verify_data` bytes for the local role.
    ///
    /// # Errors
    /// Returns [`Error::StateError`] when required TLS handshake traffic secrets are unavailable.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_compute_finished_verify_data(&self) -> Result<Vec<u8>> {
        let hash = self.noxtls_transcript_hash();
        match self.version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => {
                let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
                let hash_len = noxtls_hash_algorithm.output_len();
                let traffic_secret = if self.tls_role == TlsRole::Server {
                    self.tls13_server_handshake_traffic_secret
                        .as_ref()
                        .ok_or(Error::StateError(
                            "tls13 server handshake traffic secret must be installed before server finished",
                        ))?
                } else {
                    self.tls13_client_handshake_traffic_secret
                        .as_ref()
                        .ok_or(Error::StateError(
                            "tls13 client handshake traffic secret must be installed before client finished",
                        ))?
                };
                let finished_key = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    traffic_secret,
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
            _ => self.noxtls_compute_expected_finished(),
        }
    }

    /// Rotates TLS 1.3 application traffic secrets and record keys.
    ///
    /// # Arguments
    /// * `self` — Finished TLS 1.3 connection.
    ///
    /// # Returns
    /// `Ok(())` after both client/server application secrets are advanced.
    ///
    /// # Errors
    /// Returns [`Error::StateError`] when called before handshake completion or before application secrets are installed.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_update_tls13_traffic_keys(&mut self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 traffic key noxtls_update is only valid for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "tls13 traffic key noxtls_update requires finished handshake",
            ));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let client_secret = self
            .tls13_client_application_traffic_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 application client traffic secret is not installed",
            ))?;
        let server_secret = self
            .tls13_server_application_traffic_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 application server traffic secret is not installed",
            ))?;
        let next_client_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_secret,
            b"traffic upd",
            &[],
            hash_len,
        )?;
        let next_server_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_secret,
            b"traffic upd",
            &[],
            hash_len,
        )?;
        self.noxtls_install_tls13_record_protection_keys(
            noxtls_hash_algorithm,
            &next_client_secret,
            &next_server_secret,
        )?;
        self.tls13_client_application_traffic_secret = Some(next_client_secret);
        self.tls13_server_application_traffic_secret = Some(next_server_secret);
        self.client_sequence = 0;
        self.server_sequence = 0;
        Ok(())
    }

    /// Returns a snapshot of the TLS 1.3 resumption master secret.
    ///
    /// # Arguments
    /// * `self` — Connection expected to be in finished state.
    ///
    /// # Returns
    /// On success, cloned resumption master secret bytes.
    ///
    /// # Errors
    /// Returns [`Error::StateError`] when handshake state is incomplete or the secret is absent.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_tls13_resumption_master_secret(&self) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "resumption master secret is only defined for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "resumption master secret requires finished handshake state",
            ));
        }
        self.noxtls_tls13_resumption_master_secret
            .clone()
            .ok_or(Error::StateError(
                "tls13 resumption master secret is not installed",
            ))
    }

    /// Derives a TLS 1.3 resumption PSK using `ticket_nonce`.
    ///
    /// # Arguments
    /// * `self` — Finished TLS 1.3 connection with installed resumption secret.
    /// * `ticket_nonce` — `NewSessionTicket.ticket_nonce` bytes; must be non-empty.
    ///
    /// # Returns
    /// On success, a PSK sized to the negotiated hash output length.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] when `ticket_nonce` is empty or [`Error::StateError`] when required secrets are unavailable.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_derive_tls13_resumption_psk(&self, ticket_nonce: &[u8]) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "resumption psk derivation is only defined for TLS 1.3",
            ));
        }
        if ticket_nonce.is_empty() {
            return Err(Error::InvalidLength("ticket nonce must not be empty"));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let resumption_master = self
            .noxtls_tls13_resumption_master_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 resumption master secret is not installed",
            ))?;
        noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            resumption_master,
            b"resumption",
            ticket_nonce,
            hash_len,
        )
    }

    /// Derives client early-data record key/IV from PSK and transcript.
    ///
    /// # Arguments
    /// * `self` — Connection carrying transcript state and selected suite policy.
    /// * `psk` — Early-data PSK bytes.
    ///
    /// # Returns
    /// On success, `(aead_key, nonce_iv)` for TLS 1.3 early-data record protection.
    ///
    /// # Errors
    /// Returns KDF expansion errors from [`noxtls_tls13_expand_label_for_hash`].
    ///
    /// # Panics
    /// This function does not panic.
    pub(super) fn noxtls_derive_tls13_early_data_record_key_iv(
        &self,
        psk: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12])> {
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let noxtls_transcript_hash = noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, &self.transcript);
        let early_secret = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, psk);
        let client_early_traffic_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &early_secret,
            b"c e traffic",
            &noxtls_transcript_hash,
            hash_len,
        )?;
        let key_len = self.noxtls_tls13_early_data_key_len();
        let key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &client_early_traffic_secret,
            b"key",
            &[],
            key_len,
        )?;
        let iv: [u8; 12] = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &client_early_traffic_secret,
            b"iv",
            &[],
            12,
        )?
        .try_into()
        .expect("tls13 early-data iv should be 12 bytes");
        Ok((key, iv))
    }

    /// Installs handshake-epoch record keys for TLS 1.2/1.3 families.
    ///
    /// # Arguments
    /// * `self` — Connection receiving derived write keys and IVs.
    /// * `noxtls_hash_algorithm` — Hash policy for HKDF/label expansion.
    /// * `secret` — Handshake secret input.
    /// * `noxtls_transcript_hash` — Transcript hash for TLS 1.3 traffic-secret derivation.
    ///
    /// # Returns
    /// `Ok(())` when write keys/IVs are installed.
    ///
    /// # Errors
    /// Returns key-derivation errors when HKDF expansion fails.
    ///
    /// # Panics
    /// This function does not panic.
    pub(super) fn noxtls_install_traffic_keys(
        &mut self,
        noxtls_hash_algorithm: HashAlgorithm,
        secret: &[u8],
        noxtls_transcript_hash: &[u8],
    ) -> Result<()> {
        let (client_key, server_key, client_iv, server_iv) = match self.version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => {
                let hash_len = noxtls_hash_algorithm.output_len();
                let client_hs_traffic = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    secret,
                    b"c hs traffic",
                    noxtls_transcript_hash,
                    hash_len,
                )?;
                let server_hs_traffic = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    secret,
                    b"s hs traffic",
                    noxtls_transcript_hash,
                    hash_len,
                )?;
                self.tls13_client_handshake_traffic_secret = Some(client_hs_traffic.clone());
                self.tls13_server_handshake_traffic_secret = Some(server_hs_traffic.clone());
                self.noxtls_install_tls13_record_protection_keys(
                    noxtls_hash_algorithm,
                    &client_hs_traffic,
                    &server_hs_traffic,
                )?;
                return Ok(());
            }
            TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                let client_key_16: [u8; 16] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"client_write_key", 16)?
                        .try_into()
                        .expect("hkdf output length should be 16");
                let server_key_16: [u8; 16] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"server_write_key", 16)?
                        .try_into()
                        .expect("hkdf output length should be 16");
                let mut client_key = [0_u8; 32];
                let mut server_key = [0_u8; 32];
                client_key[..16].copy_from_slice(&client_key_16);
                server_key[..16].copy_from_slice(&server_key_16);
                let client_iv: [u8; 12] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"client_write_iv", 12)?
                        .try_into()
                        .expect("hkdf output length should be 12");
                let server_iv: [u8; 12] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"server_write_iv", 12)?
                        .try_into()
                        .expect("hkdf output length should be 12");
                (client_key, server_key, client_iv, server_iv)
            }
        };
        self.client_write_key = Some(client_key);
        self.server_write_key = Some(server_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_iv = Some(server_iv);
        self.noxtls_sync_dtls13_traffic_keys_from_record_protection_state();
        Ok(())
    }

    /// Installs TLS 1.3 application traffic secrets and record keys.
    ///
    /// # Arguments
    /// * `self` — Connection with established handshake secret.
    ///
    /// # Returns
    /// `Ok(())` after installing application traffic and exporter/resumption secrets.
    ///
    /// # Errors
    /// Returns [`Error::StateError`] when handshake secret is unavailable or label expansion fails.
    ///
    /// # Panics
    /// This function does not panic.
    pub(super) fn noxtls_install_tls13_application_traffic_keys(&mut self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Ok(());
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let noxtls_transcript_hash = self.noxtls_transcript_hash();
        let handshake_secret = self.handshake_secret.as_ref().ok_or(Error::StateError(
            "handshake secret must be available before tls13 application traffic keys",
        ))?;
        let derived = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            handshake_secret,
            b"derived",
            &noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, &[]),
            hash_len,
        )?;
        let zero_ikm = vec![0_u8; hash_len];
        let master_secret =
            noxtls_hkdf_extract_with_salt_for_hash(noxtls_hash_algorithm, &derived, &zero_ikm);
        let client_app_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &master_secret,
            b"c ap traffic",
            &noxtls_transcript_hash,
            hash_len,
        )?;
        let server_app_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &master_secret,
            b"s ap traffic",
            &noxtls_transcript_hash,
            hash_len,
        )?;
        self.noxtls_install_tls13_record_protection_keys(
            noxtls_hash_algorithm,
            &client_app_secret,
            &server_app_secret,
        )?;
        self.noxtls_install_tls13_exporter_and_resumption_secrets(
            noxtls_hash_algorithm,
            &master_secret,
            &noxtls_transcript_hash,
        )?;
        self.tls13_master_secret = Some(master_secret);
        self.tls13_client_application_traffic_secret = Some(client_app_secret);
        self.tls13_server_application_traffic_secret = Some(server_app_secret);
        self.client_sequence = 0;
        self.server_sequence = 0;
        Ok(())
    }

    /// Derives exporter and resumption master secrets from TLS 1.3 master secret.
    ///
    /// # Arguments
    /// * `self` — Connection receiving derived secret snapshots.
    /// * `noxtls_hash_algorithm` — Negotiated transcript hash algorithm.
    /// * `master_secret` — TLS 1.3 master secret bytes.
    /// * `noxtls_transcript_hash` — Transcript hash for label context binding.
    ///
    /// # Returns
    /// `Ok(())` after both secrets are updated on the connection.
    ///
    /// # Errors
    /// Returns KDF expansion errors from [`noxtls_tls13_expand_label_for_hash`].
    ///
    /// # Panics
    /// This function does not panic.
    fn noxtls_install_tls13_exporter_and_resumption_secrets(
        &mut self,
        noxtls_hash_algorithm: HashAlgorithm,
        master_secret: &[u8],
        noxtls_transcript_hash: &[u8],
    ) -> Result<()> {
        let hash_len = noxtls_hash_algorithm.output_len();
        self.tls13_exporter_master_secret = Some(noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            master_secret,
            b"exp master",
            noxtls_transcript_hash,
            hash_len,
        )?);
        self.noxtls_tls13_resumption_master_secret = Some(noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            master_secret,
            b"res master",
            noxtls_transcript_hash,
            hash_len,
        )?);
        Ok(())
    }

    /// Installs TLS 1.3 record-protection keys and IVs from traffic secrets.
    ///
    /// # Arguments
    /// * `self` — Connection receiving key/IV state updates.
    /// * `noxtls_hash_algorithm` — Hash policy for label expansion.
    /// * `client_traffic_secret` — Client traffic secret bytes.
    /// * `server_traffic_secret` — Server traffic secret bytes.
    ///
    /// # Returns
    /// `Ok(())` when key/IV material is copied into write-state fields.
    ///
    /// # Errors
    /// Returns [`Error::StateError`] for missing/invalid suite context or KDF expansion failures.
    ///
    /// # Panics
    /// This function does not panic.
    pub(super) fn noxtls_install_tls13_record_protection_keys(
        &mut self,
        noxtls_hash_algorithm: HashAlgorithm,
        client_traffic_secret: &[u8],
        server_traffic_secret: &[u8],
    ) -> Result<()> {
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before tls13 record protection keys",
        ))?;
        let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
            "tls 1.3 record protection requires a tls 1.3 AEAD cipher suite",
        ))?;
        let client_key_material = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_traffic_secret,
            b"key",
            &[],
            key_len,
        )?;
        let server_key_material = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_traffic_secret,
            b"key",
            &[],
            key_len,
        )?;
        let mut client_key = [0_u8; 32];
        let mut server_key = [0_u8; 32];
        client_key[..key_len].copy_from_slice(&client_key_material);
        server_key[..key_len].copy_from_slice(&server_key_material);
        let client_iv: [u8; 12] = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_traffic_secret,
            b"iv",
            &[],
            12,
        )?
        .try_into()
        .expect("tls13 iv length should be 12");
        let server_iv: [u8; 12] = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_traffic_secret,
            b"iv",
            &[],
            12,
        )?
        .try_into()
        .expect("tls13 iv length should be 12");
        self.client_write_key = Some(client_key);
        self.server_write_key = Some(server_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_iv = Some(server_iv);
        self.noxtls_sync_dtls13_traffic_keys_from_record_protection_state();
        Ok(())
    }

    /// Resolves the active handshake hash algorithm.
    ///
    /// # Arguments
    /// * `self` — Connection whose negotiated suite or transcript state provides hash policy.
    ///
    /// # Returns
    /// Negotiated suite hash when available, otherwise transcript-hash fallback.
    ///
    /// # Panics
    /// This function does not panic.
    pub(super) fn noxtls_negotiated_hash_algorithm(&self) -> HashAlgorithm {
        self.noxtls_selected_cipher_suite
            .map(CipherSuite::noxtls_hash_algorithm)
            .unwrap_or_else(|| self.noxtls_transcript_hash.noxtls_algorithm())
    }
}

/// Derives TLS 1.3 handshake secret from shared secret input material.
///
/// # Arguments
/// * `noxtls_hash_algorithm` — Hash policy used by HKDF extract/expand.
/// * `shared_secret` — ECDHE or hybrid shared-secret bytes.
/// * `suite` — Optional selected suite to align hash choice when needed.
///
/// # Returns
/// On success, derived handshake secret bytes.
///
/// # Errors
/// Returns KDF expansion errors propagated from label expansion.
///
/// # Panics
/// This function does not panic.
pub(super) fn noxtls_derive_tls13_handshake_secret(
    noxtls_hash_algorithm: HashAlgorithm,
    shared_secret: &[u8],
    suite: Option<CipherSuite>,
) -> Result<Vec<u8>> {
    let hash_len = noxtls_hash_algorithm.output_len();
    let zero_psk = vec![0_u8; hash_len];
    let early_secret = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, &zero_psk);
    noxtls_tls13_debug_log_bytes("tls13.kdf.early_secret", &early_secret);
    let empty_hash = noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, &[]);
    let derived = noxtls_tls13_expand_label_for_hash(
        noxtls_hash_algorithm,
        &early_secret,
        b"derived",
        &empty_hash,
        hash_len,
    )?;
    noxtls_tls13_debug_log_bytes("tls13.kdf.derived_secret", &derived);
    let mut handshake_secret =
        noxtls_hkdf_extract_with_salt_for_hash(noxtls_hash_algorithm, &derived, shared_secret);
    if let Some(selected) = suite {
        if selected.noxtls_hash_algorithm() != noxtls_hash_algorithm {
            handshake_secret = noxtls_hkdf_extract_with_salt_for_hash(
                selected.noxtls_hash_algorithm(),
                &derived,
                shared_secret,
            );
        }
    }
    Ok(handshake_secret)
}

/// Computes TLS 1.2 PRF output using the selected hash algorithm.
///
/// # Arguments
/// * `noxtls_hash_algorithm` — PRF hash selector (`SHA-256` or `SHA-384`).
/// * `secret` — PRF secret bytes.
/// * `label` — PRF label bytes.
/// * `seed` — PRF seed bytes.
/// * `len` — Output length in bytes.
///
/// # Returns
/// On success, PRF output with exactly `len` bytes.
///
/// # Errors
/// Returns PRF derivation errors from the selected hash-specific implementation.
///
/// # Panics
/// This function does not panic.
pub(super) fn noxtls_tls12_prf_for_hash(
    noxtls_hash_algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_tls12_prf_sha256(secret, label, seed, len),
        HashAlgorithm::Sha384 => noxtls_tls12_prf_sha384(secret, label, seed, len),
    }
}
