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

//! TLS 1.3 handshake message construction, validation, and key schedule transitions.

use super::*;

impl Connection {
    /// Builds a minimal TLS 1.3 Certificate handshake message with one certificate entry.
    ///
    /// # Arguments
    /// * `certificate_der`: DER-encoded certificate bytes.
    ///
    /// # Returns
    /// Encoded Certificate message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_certificate_message(certificate_der: &[u8]) -> Result<Vec<u8>> {
        Self::noxtls_build_certificate_message_with_ocsp_staple(certificate_der, None)
    }

    /// Builds a TLS 1.3 Certificate handshake message with optional leaf OCSP staple.
    ///
    /// # Arguments
    /// * `certificate_der`: DER-encoded certificate bytes.
    /// * `ocsp_staple`: Optional stapled OCSP response bytes for leaf certificate entry.
    ///
    /// # Returns
    /// Encoded Certificate message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    pub fn noxtls_build_certificate_message_with_ocsp_staple(
        certificate_der: &[u8],
        ocsp_staple: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if certificate_der.is_empty() {
            return Err(Error::InvalidLength("certificate der must not be empty"));
        }
        if certificate_der.len() > 0x00FF_FFFF {
            return Err(Error::InvalidLength("certificate der is too large"));
        }
        let certificate_extensions = if let Some(staple) = ocsp_staple {
            noxtls_encode_certificate_entry_status_request_extension(staple)?
        } else {
            Vec::new()
        };
        let mut body = Vec::new();
        body.push(0x00); // certificate_request_context length
        let cert_entry_len = 3 + certificate_der.len() + 2 + certificate_extensions.len();
        let list_len = cert_entry_len as u32;
        body.extend_from_slice(&list_len.to_be_bytes()[1..4]);
        let cert_len = certificate_der.len() as u32;
        body.extend_from_slice(&cert_len.to_be_bytes()[1..4]);
        body.extend_from_slice(certificate_der);
        body.extend_from_slice(&(certificate_extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&certificate_extensions);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_CERTIFICATE,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 CertificateVerify handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded CertificateVerify handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_certificate_verify(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "certificate verify can only be processed after certificate",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_CERTIFICATE_VERIFY {
            return Err(Error::ParseFailure("invalid certificate verify type"));
        }
        let (signature_scheme, signature) = noxtls_parse_certificate_verify_fields(body)?;
        if signature.is_empty() {
            return Err(Error::ParseFailure(
                "certificate verify signature must not be empty",
            ));
        }
        if !noxtls_tls13_supported_certificate_verify_signature_scheme(signature_scheme) {
            return Err(Error::UnsupportedFeature(
                "unsupported tls13 certificate verify signature scheme",
            ));
        }
        if self.tls13_require_certificate_auth {
            if !self.tls13_server_certificate_chain_validated {
                return Err(Error::StateError(
                    "certificate verify requires validated server certificate chain",
                ));
            }
            self.noxtls_verify_tls13_server_certificate_verify_signature(signature_scheme, signature)?;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateVerified;
        Ok(())
    }

    /// Builds a minimal TLS 1.3 CertificateVerify handshake message.
    ///
    /// # Arguments
    /// * `signature_scheme`: Signature scheme identifier.
    /// * `signature`: Signature bytes.
    ///
    /// # Returns
    /// Encoded CertificateVerify message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_certificate_verify_message(
        signature_scheme: u16,
        signature: &[u8],
    ) -> Result<Vec<u8>> {
        if signature.is_empty() {
            return Err(Error::InvalidLength(
                "certificate verify signature must not be empty",
            ));
        }
        if signature.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidLength(
                "certificate verify signature is too large",
            ));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&signature_scheme.to_be_bytes());
        body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        body.extend_from_slice(signature);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_CERTIFICATE_VERIFY,
            &body,
        ))
    }

    /// Derives a prototype handshake secret from the selected transcript hash bytes.
    ///
    /// # Arguments
    /// * `self`: Connection with ServerHello already processed.
    ///
    /// # Returns
    /// 32-byte derived handshake secret.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_derive_handshake_secret(&mut self) -> Result<[u8; 32]> {
        if self.version.uses_tls13_handshake_semantics() {
            let allowed_state = if self.tls_role == TlsRole::Server {
                self.state == HandshakeState::ServerHelloSent
            } else {
                self.state == HandshakeState::ServerHelloReceived
            };
            if !allowed_state {
                return Err(Error::StateError(
                    "tls13 handshake traffic keys require server hello processing",
                ));
            }
        } else if self.state != HandshakeState::ServerHelloReceived
            && self.state != HandshakeState::ServerCertificateVerified
        {
            return Err(Error::StateError(
                "cannot derive handshake secret before server hello",
            ));
        }
        let noxtls_transcript_hash = self.noxtls_transcript_hash();
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        noxtls_tls13_debug_log(
            "tls13.kdf.hash_algorithm",
            noxtls_hash_algorithm_name(noxtls_hash_algorithm),
        );
        noxtls_tls13_debug_log_bytes("tls13.kdf.transcript_hash", &noxtls_transcript_hash);
        if self.version.uses_tls13_handshake_semantics() {
            if let Some(secret) = self.tls13_shared_secret.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.kdf.shared_secret_input", secret);
            } else {
                noxtls_tls13_debug_log("tls13.kdf.shared_secret_input", "none");
            }
        }
        let secret_material = match self.version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => noxtls_derive_tls13_handshake_secret(
                noxtls_hash_algorithm,
                self.tls13_shared_secret
                    .as_ref()
                    .map_or(&noxtls_transcript_hash, |secret| secret),
                self.noxtls_selected_cipher_suite,
            )?,
            TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                let prk = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, &noxtls_transcript_hash);
                noxtls_tls12_prf_for_hash(
                    noxtls_hash_algorithm,
                    &prk,
                    b"handshake secret",
                    &noxtls_transcript_hash,
                    32,
                )?
            }
            TlsVersion::Tls10 | TlsVersion::Tls11 => {
                let prk = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, &noxtls_transcript_hash);
                noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, &prk, b"handshake secret", 32)?
            }
        };
        noxtls_tls13_debug_log_bytes("tls13.kdf.handshake_secret", &secret_material);
        self.noxtls_install_traffic_keys(noxtls_hash_algorithm, &secret_material, &noxtls_transcript_hash)?;
        if self.version.uses_tls13_handshake_semantics() {
            if let Some(secret) = self.tls13_client_handshake_traffic_secret.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.kdf.client_hs_traffic_secret", secret);
            }
            if let Some(secret) = self.tls13_server_handshake_traffic_secret.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.kdf.server_hs_traffic_secret", secret);
            }
            if let Some(key) = self.client_write_key.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.client_write_key", key);
            }
            if let Some(key) = self.server_write_key.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.server_write_key", key);
            }
            if let Some(iv) = self.client_write_iv.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.client_write_iv", iv);
            }
            if let Some(iv) = self.server_write_iv.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.server_write_iv", iv);
            }
        }
        self.handshake_secret = Some(secret_material.clone());
        let mut secret = [0_u8; 32];
        let copy_len = secret_material.len().min(32);
        secret[..copy_len].copy_from_slice(&secret_material[..copy_len]);
        self.state = HandshakeState::KeysDerived;
        Ok(secret)
    }

    /// Finalizes the handshake and records verify data in transcript history.
    ///
    /// # Arguments
    /// * `verify_data`: Finished verify_data bytes to validate and record.
    ///
    /// # Returns
    /// `Ok(())` when Finished verification succeeds.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_finish(&mut self, verify_data: &[u8]) -> Result<()> {
        if self.state != HandshakeState::KeysDerived
            && self.state != HandshakeState::ServerCertificateVerified
        {
            return Err(Error::StateError("noxtls_finish must follow key derivation"));
        }
        let expected = self.noxtls_compute_expected_finished()?;
        if verify_data != expected.as_slice() {
            return Err(Error::CryptoFailure("finished verify_data mismatch"));
        }
        if self.version.uses_tls13_handshake_semantics() {
            let finished_message = noxtls_encode_handshake_message(HANDSHAKE_FINISHED, verify_data);
            self.noxtls_append_transcript(&finished_message);
        } else {
            self.noxtls_append_transcript(verify_data);
        }
        self.state = HandshakeState::Finished;
        Ok(())
    }

    /// Parses a TLS 1.3 Finished handshake wrapper and validates verify_data.
    ///
    /// # Arguments
    /// * `msg`: Encoded Finished handshake message.
    ///
    /// # Returns
    /// `Ok(())` when Finished verifies and state transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_finished_message(&mut self, msg: &[u8]) -> Result<()> {
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_FINISHED {
            return Err(Error::ParseFailure("invalid finished type"));
        }
        if self.state != HandshakeState::KeysDerived
            && self.state != HandshakeState::ServerCertificateVerified
        {
            return Err(Error::StateError("noxtls_finish must follow key derivation"));
        }
        let expected_len = self.noxtls_compute_expected_finished()?.len();
        if body.len() != expected_len {
            return Err(Error::ParseFailure("finished verify_data length mismatch"));
        }
        self.noxtls_finish(body)
    }

    /// Activates TLS 1.3 application traffic keys after local Finished has been sent.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    ///
    /// `Ok(())` when application traffic keys are installed for post-handshake records.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called outside TLS 1.3 `Finished` state or when
    /// key-schedule material is unavailable.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_activate_tls13_application_traffic_keys(&mut self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "application traffic key activation requires TLS 1.3 connection",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "application traffic keys can only be activated in finished state",
            ));
        }
        self.noxtls_install_tls13_application_traffic_keys()
    }

    /// Builds local TLS 1.3 Finished handshake message from current transcript state.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Encoded Finished handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_finished_message(&self) -> Result<Vec<u8>> {
        let verify_data = self.noxtls_compute_finished_verify_data()?;
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_FINISHED,
            &verify_data,
        ))
    }

    /// Builds a TLS Finished handshake message for the **peer** (e.g. server's Finished on a client `Connection`).
    ///
    /// This wraps [`Self::noxtls_compute_expected_finished`] as a handshake message. Use this when
    /// modeling inbound server Finished bytes; use [`Self::noxtls_build_finished_message`] for the
    /// local endpoint's Finished to transmit.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// Encoded `Finished` handshake message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_peer_finished_message(&self) -> Result<Vec<u8>> {
        let verify_data = self.noxtls_compute_expected_finished()?;
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_FINISHED,
            &verify_data,
        ))
    }

    /// Builds a minimal TLS 1.3 NewSessionTicket handshake message.
    ///
    /// # Arguments
    /// * `ticket_lifetime`: Ticket lifetime in seconds.
    /// * `ticket_age_add`: Obfuscation value for ticket age.
    /// * `ticket_nonce`: Ticket nonce bytes.
    /// * `ticket`: Opaque ticket identity bytes.
    ///
    /// # Returns
    /// Encoded NewSessionTicket message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_new_session_ticket_message(
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: &[u8],
        ticket: &[u8],
    ) -> Result<Vec<u8>> {
        if ticket_nonce.len() > usize::from(u8::MAX) {
            return Err(Error::InvalidLength("ticket nonce is too large"));
        }
        if ticket.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidLength("ticket identity is too large"));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&ticket_lifetime.to_be_bytes());
        body.extend_from_slice(&ticket_age_add.to_be_bytes());
        body.push(ticket_nonce.len() as u8);
        body.extend_from_slice(ticket_nonce);
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(ticket);
        body.extend_from_slice(&0_u16.to_be_bytes()); // extensions length
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_NEW_SESSION_TICKET,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 NewSessionTicket handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded NewSessionTicket handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_new_session_ticket_message(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "noxtls_new session ticket requires finished handshake state",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_NEW_SESSION_TICKET {
            return Err(Error::ParseFailure("invalid noxtls_new session ticket type"));
        }
        noxtls_parse_new_session_ticket_body(body)?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Builds a TLS 1.3 KeyUpdate handshake message.
    ///
    /// # Arguments
    /// * `request_update`: Whether peer should also noxtls_update its sending keys.
    ///
    /// # Returns
    /// Encoded KeyUpdate message bytes.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_key_update_message(request_update: bool) -> Vec<u8> {
        let request = if request_update { 1_u8 } else { 0_u8 };
        noxtls_encode_handshake_message(HANDSHAKE_KEY_UPDATE, &[request])
    }

    /// Parses a TLS 1.3 KeyUpdate handshake message and rotates traffic keys.
    ///
    /// # Arguments
    /// * `msg`: Encoded KeyUpdate handshake message.
    ///
    /// # Returns
    /// `Ok(())` when KeyUpdate parses and local keys rotate successfully.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_key_update_message(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "key noxtls_update requires finished handshake state",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_KEY_UPDATE {
            return Err(Error::ParseFailure("invalid key noxtls_update type"));
        }
        if body.len() != 1 || body[0] > 1 {
            return Err(Error::ParseFailure("invalid key noxtls_update request value"));
        }
        self.noxtls_update_tls13_traffic_keys()?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }
}
