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

//! QUIC-focused TLS 1.3 key-derivation helpers on `Connection`.

use super::*;

impl Connection {
    /// Derives QUIC Initial secrets for QUIC v1 using the destination connection ID.
    ///
    /// # Arguments
    /// * `destination_connection_id`: QUIC destination connection ID from the client's first Initial packet.
    ///
    /// # Returns
    /// QUIC v1 initial secret bundle containing common, client, and server initial secrets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when the destination connection ID is empty, or other [`noxtls_core::Error`] values from HKDF label expansion.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_derive_tls13_quic_initial_secrets_v1(
        destination_connection_id: &[u8],
    ) -> Result<Tls13QuicInitialSecrets> {
        if destination_connection_id.is_empty() {
            return Err(Error::InvalidLength(
                "quic destination connection id must not be empty",
            ));
        }
        let initial_secret =
            noxtls_hkdf_extract_sha256(&TLS13_QUIC_V1_INITIAL_SALT, destination_connection_id)
                .to_vec();
        let client_initial_secret = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &initial_secret,
            b"client in",
            &[],
            32,
        )?;
        let server_initial_secret = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &initial_secret,
            b"server in",
            &[],
            32,
        )?;
        Ok(Tls13QuicInitialSecrets {
            initial_secret,
            client_initial_secret,
            server_initial_secret,
        })
    }

    /// Derives QUIC packet-protection key material from one traffic secret.
    ///
    /// # Arguments
    /// * `noxtls_hash_algorithm`: Hash profile used for TLS HKDF label expansion.
    /// * `traffic_secret`: QUIC traffic secret at a specific encryption level.
    /// * `key_len`: AEAD key length in bytes.
    /// * `header_protection_key_len`: Header-protection key length in bytes.
    ///
    /// # Returns
    /// QUIC key, IV, and header-protection key derived from `traffic_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when key lengths are zero, or other [`noxtls_core::Error`] values from HKDF label expansion.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_derive_tls13_quic_packet_protection_keys(
        noxtls_hash_algorithm: HashAlgorithm,
        traffic_secret: &[u8],
        key_len: usize,
        header_protection_key_len: usize,
    ) -> Result<Tls13QuicPacketProtectionKeys> {
        if key_len == 0 {
            return Err(Error::InvalidLength(
                "quic key length must be greater than zero",
            ));
        }
        if header_protection_key_len == 0 {
            return Err(Error::InvalidLength(
                "quic header protection key length must be greater than zero",
            ));
        }
        let key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            traffic_secret,
            b"quic key",
            &[],
            key_len,
        )?;
        let iv = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            traffic_secret,
            b"quic iv",
            &[],
            12,
        )?;
        let header_protection_key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            traffic_secret,
            b"quic hp",
            &[],
            header_protection_key_len,
        )?;
        Ok(Tls13QuicPacketProtectionKeys {
            key,
            iv,
            header_protection_key,
        })
    }

    /// Returns current QUIC handshake and 1-RTT traffic secret snapshots.
    ///
    /// # Returns
    /// Bundle containing client/server handshake and application traffic secrets.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called before corresponding TLS 1.3 secrets are installed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_tls13_quic_traffic_secret_snapshot(&self) -> Result<Tls13QuicTrafficSecretSnapshot> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "quic traffic secret snapshot is only defined for TLS 1.3",
            ));
        }
        let client_handshake_secret = self
            .tls13_client_handshake_traffic_secret
            .clone()
            .ok_or(Error::StateError(
                "tls13 client handshake traffic secret is not installed",
            ))?;
        let server_handshake_secret = self
            .tls13_server_handshake_traffic_secret
            .clone()
            .ok_or(Error::StateError(
                "tls13 server handshake traffic secret is not installed",
            ))?;
        let client_application_secret =
            self.tls13_client_application_traffic_secret
                .clone()
                .ok_or(Error::StateError(
                    "tls13 client application traffic secret is not installed",
                ))?;
        let server_application_secret =
            self.tls13_server_application_traffic_secret
                .clone()
                .ok_or(Error::StateError(
                    "tls13 server application traffic secret is not installed",
                ))?;
        Ok(Tls13QuicTrafficSecretSnapshot {
            client_handshake_secret,
            server_handshake_secret,
            client_application_secret,
            server_application_secret,
        })
    }

    /// Derives next QUIC 1-RTT traffic secrets from currently installed application secrets.
    ///
    /// # Returns
    /// Next-generation client/server application secrets derived via `quic ku`.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called before TLS 1.3 application secrets are installed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_derive_tls13_quic_next_traffic_secrets(&self) -> Result<Tls13QuicNextTrafficSecrets> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "quic key noxtls_update secrets are only defined for TLS 1.3",
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
        let client_next_application_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_secret,
            b"quic ku",
            &[],
            hash_len,
        )?;
        let server_next_application_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_secret,
            b"quic ku",
            &[],
            hash_len,
        )?;
        Ok(Tls13QuicNextTrafficSecrets {
            client_next_application_secret,
            server_next_application_secret,
        })
    }

    /// Exports QUIC-specific keying material using `EXPORTER-QUIC ...` labels.
    ///
    /// # Arguments
    /// * `label`: QUIC exporter label, for example [`TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT`].
    /// * `context`: Exporter context bytes.
    /// * `len`: Requested output length in bytes.
    ///
    /// # Returns
    /// Exported keying material bytes bound to transcript and QUIC exporter label.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when label namespace is not QUIC, or other exporter errors from [`Self::noxtls_export_keying_material`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_export_quic_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        if !label.starts_with(b"EXPORTER-QUIC ") {
            return Err(Error::StateError(
                "quic exporter requires label prefix EXPORTER-QUIC ",
            ));
        }
        self.noxtls_export_keying_material(label, context, len)
    }
}
