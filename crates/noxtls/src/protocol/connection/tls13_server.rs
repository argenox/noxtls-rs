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

//! TLS 1.3 server-flight parsing, policy enforcement, and handshake sequencing.

use super::*;

impl Connection {
    /// Validates and records server hello bytes for transcript hashing.
    ///
    /// # Arguments
    /// * `msg`: Encoded ServerHello handshake message.
    ///
    /// # Returns
    /// `Ok(())` when ServerHello parses and state advances.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_server_hello(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ClientHelloSent {
            return Err(Error::StateError(
                "server hello can only be processed after client hello",
            ));
        }
        let parsed = noxtls_parse_server_hello(msg)?;
        if parsed.hello_retry_request {
            if self.tls13_hrr_seen {
                return Err(Error::ParseFailure("duplicate hello retry request"));
            }
            self.tls13_hrr_seen = true;
            self.tls13_hrr_requested_group = parsed.requested_group;
            self.noxtls_reset_transcript_for_hrr();
            self.noxtls_append_transcript(msg);
            self.state = HandshakeState::Idle;
            return Ok(());
        }
        let selected_suite = parsed.suite;
        self.tls13_hrr_seen = false;
        self.tls13_hrr_requested_group = None;
        let server_key_share = parsed.key_share;
        if let Some(share) = server_key_share {
            self.tls13_shared_secret = Some(match share {
                Tls13ServerKeyShareParsed::X25519(peer_key_share) => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.x25519",
                        &peer_key_share,
                    );
                    let private = self.tls13_client_x25519_private.clone().ok_or(
                        Error::StateError(
                            "client x25519 key share must be available before server x25519 key share",
                        ),
                    )?;
                    let shared =
                        noxtls_derive_tls13_x25519_shared_secret(private, &peer_key_share)?.to_vec();
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
                Tls13ServerKeyShareParsed::Secp256r1(peer_uncompressed) => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.secp256r1",
                        &peer_uncompressed,
                    );
                    let private = self.tls13_client_p256_private.as_ref().ok_or(
                        Error::StateError(
                            "client secp256r1 key share must be available before server secp256r1 key share",
                        ),
                    )?;
                    let shared =
                        noxtls_derive_tls13_p256_shared_secret(private, &peer_uncompressed)?.to_vec();
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
                Tls13ServerKeyShareParsed::MlKem768(peer_key_share) => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.mlkem768_ciphertext",
                        &peer_key_share,
                    );
                    let private = self.tls13_client_mlkem768_private.as_ref().ok_or(
                        Error::StateError(
                            "client mlkem768 key share must be available before server mlkem768 key share",
                        ),
                    )?;
                    let shared =
                        noxtls_derive_tls13_mlkem768_shared_secret(private, &peer_key_share)?.to_vec();
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
                Tls13ServerKeyShareParsed::X25519MlKem768Hybrid { x25519, mlkem768 } => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.hybrid.x25519",
                        &x25519,
                    );
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.hybrid.mlkem768_ciphertext",
                        &mlkem768,
                    );
                    let x25519_private = self.tls13_client_x25519_private.clone().ok_or(
                        Error::StateError(
                            "client x25519 key share must be available before server hybrid key share",
                        ),
                    )?;
                    let x25519_shared =
                        noxtls_derive_tls13_x25519_shared_secret(x25519_private, &x25519)?;
                    let mlkem_private = self.tls13_client_mlkem768_private.as_ref().ok_or(
                        Error::StateError(
                            "client mlkem768 key share must be available before server hybrid key share",
                        ),
                    )?;
                    let mlkem_shared =
                        noxtls_derive_tls13_mlkem768_shared_secret(mlkem_private, &mlkem768)?;
                    let shared = noxtls_combine_tls13_hybrid_shared_secret(
                        x25519_shared.as_slice(),
                        mlkem_shared.as_slice(),
                    );
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret.classical", &x25519_shared);
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret.pq", &mlkem_shared);
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
            });
        }
        noxtls_tls13_debug_log_bytes("tls13.transcript.server_hello", msg);
        self.noxtls_append_transcript(msg);
        self.noxtls_selected_cipher_suite = Some(selected_suite);
        self.noxtls_rebuild_transcript_hash_from_selected_suite();
        self.state = HandshakeState::ServerHelloReceived;
        Ok(())
    }

    /// Builds a TLS 1.3 HelloRetryRequest (ServerHello form) with requested group.
    ///
    /// # Arguments
    /// * `suite`: Selected cipher suite to advertise.
    /// * `requested_group`: Named group requested for retried key share.
    ///
    /// # Returns
    /// Encoded HelloRetryRequest handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_hello_retry_request(
        suite: CipherSuite,
        requested_group: u16,
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&noxtls_legacy_wire_version(TlsVersion::Tls13));
        body.extend_from_slice(&TLS13_HRR_RANDOM);
        body.push(0x00); // session_id length
        body.extend_from_slice(&suite.noxtls_to_u16().to_be_bytes());
        body.push(0x00); // compression method
        let mut extensions = Vec::new();
        noxtls_push_extension(
            &mut extensions,
            EXT_KEY_SHARE,
            &requested_group.to_be_bytes(),
        );
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_SERVER_HELLO,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 EncryptedExtensions handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded EncryptedExtensions handshake message.
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
    pub fn noxtls_recv_encrypted_extensions(&mut self, msg: &[u8]) -> Result<()> {
        let allowed = if self.version.uses_tls13_handshake_semantics() {
            self.state == HandshakeState::ServerHelloReceived
                || self.state == HandshakeState::KeysDerived
        } else {
            self.state == HandshakeState::ServerHelloReceived
        };
        if !allowed {
            return Err(Error::StateError(
                "encrypted extensions can only be processed after server hello",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_ENCRYPTED_EXTENSIONS {
            return Err(Error::ParseFailure("invalid encrypted extensions type"));
        }
        let encrypted_extensions = noxtls_parse_encrypted_extensions_body(body)?;
        if encrypted_extensions.server_name_acknowledged && self.tls13_client_server_name.is_none() {
            return Err(Error::ParseFailure(
                "encrypted extensions contains unsolicited server_name acknowledgement",
            ));
        }
        if self.tls13_require_server_name_ack
            && self.tls13_client_server_name.is_some()
            && !encrypted_extensions.server_name_acknowledged
        {
            return Err(Error::ParseFailure(
                "encrypted extensions missing required server_name acknowledgement",
            ));
        }
        if encrypted_extensions.early_data_accepted && !self.tls13_early_data_offered_in_client_hello {
            return Err(Error::ParseFailure(
                "encrypted extensions contains unsolicited early_data acceptance",
            ));
        }
        self.tls13_early_data_accepted_in_encrypted_extensions = encrypted_extensions.early_data_accepted;
        if self.tls13_early_data_offered_in_client_hello && !encrypted_extensions.early_data_accepted {
            self.tls13_early_data_accepted_psk = None;
            self.tls13_early_data_max_bytes = None;
            self.tls13_early_data_opened_bytes = 0;
            self.tls13_early_data_replay_window = DtlsReplayWindow::noxtls_new();
        }
        self.noxtls_tls13_server_name_acknowledged = encrypted_extensions.server_name_acknowledged;
        if let Some(selected_protocol) = encrypted_extensions.selected_alpn_protocol {
            if !self.tls13_client_alpn_protocols.is_empty()
                && !self.tls13_client_alpn_protocols.contains(&selected_protocol)
            {
                return Err(Error::ParseFailure(
                    "encrypted extensions selected unsupported alpn protocol",
                ));
            }
            self.noxtls_tls13_selected_alpn_protocol = Some(selected_protocol);
        } else {
            self.noxtls_tls13_selected_alpn_protocol = None;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerEncryptedExtensionsReceived;
        Ok(())
    }

    /// Builds a minimal TLS 1.3 CertificateRequest handshake message.
    ///
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    /// Encoded CertificateRequest bytes.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_certificate_request_message() -> Vec<u8> {
        // Empty request context + signature_algorithms extension.
        let mut extensions = Vec::new();
        let mut sigalgs = Vec::new();
        let requested_sigalgs = [
            TLS13_SIGALG_ECDSA_SECP256R1_SHA256,
            TLS13_SIGALG_ECDSA_SECP384R1_SHA384,
            TLS13_SIGALG_RSA_PSS_RSAE_SHA256,
            TLS13_SIGALG_RSA_PSS_RSAE_SHA384,
            TLS13_SIGALG_ED25519,
            TLS13_SIGALG_MLDSA65,
        ];
        sigalgs.extend_from_slice(&((requested_sigalgs.len() * 2) as u16).to_be_bytes());
        for sigalg in requested_sigalgs {
            sigalgs.extend_from_slice(&sigalg.to_be_bytes());
        }
        noxtls_push_extension(&mut extensions, EXT_SIGNATURE_ALGORITHMS, &sigalgs);
        let mut body = Vec::new();
        body.push(0x00); // certificate_request_context length
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        noxtls_encode_handshake_message(HANDSHAKE_CERTIFICATE_REQUEST, &body)
    }

    /// Parses and records a TLS 1.3 CertificateRequest handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded CertificateRequest handshake message.
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
    pub fn noxtls_recv_certificate_request(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerEncryptedExtensionsReceived {
            return Err(Error::StateError(
                "certificate request can only be processed after encrypted extensions",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_CERTIFICATE_REQUEST {
            return Err(Error::ParseFailure("invalid certificate request type"));
        }
        noxtls_parse_certificate_request_body(body)?;
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateRequestReceived;
        Ok(())
    }

    /// Builds a minimal TLS 1.3 EncryptedExtensions handshake message.
    ///
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_encrypted_extensions() -> Vec<u8> {
        // Minimal empty extension block.
        Self::noxtls_build_encrypted_extensions_with_policy(None, false, false)
            .expect("empty encrypted extensions must always encode")
    }

    /// Builds a TLS 1.3 EncryptedExtensions handshake message with optional ALPN.
    ///
    /// # Arguments
    /// * `selected_alpn`: Selected ALPN protocol bytes to advertise to client, or `None`.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_encrypted_extensions_with_alpn(
        selected_alpn: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Self::noxtls_build_encrypted_extensions_with_policy(selected_alpn, false, false)
    }

    /// Builds a TLS 1.3 EncryptedExtensions handshake message with optional ALPN and early_data ack.
    ///
    /// # Arguments
    /// * `selected_alpn`: Selected ALPN protocol bytes to advertise to client, or `None`.
    /// * `accept_early_data`: `true` emits empty early_data extension.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_build_encrypted_extensions_with_alpn_and_early_data(
        selected_alpn: Option<&[u8]>,
        accept_early_data: bool,
    ) -> Result<Vec<u8>> {
        Self::noxtls_build_encrypted_extensions_with_policy(selected_alpn, false, accept_early_data)
    }

    /// Builds a TLS 1.3 EncryptedExtensions handshake message with ALPN and SNI-ack policy.
    ///
    /// # Arguments
    /// * `selected_alpn`: Selected ALPN protocol bytes to advertise to client, or `None`.
    /// * `acknowledge_server_name`: `true` emits empty server_name extension as SNI acknowledgment.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_encrypted_extensions_with_policy(
        selected_alpn: Option<&[u8]>,
        acknowledge_server_name: bool,
        accept_early_data: bool,
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut extensions = Vec::new();
        if let Some(protocol) = selected_alpn {
            if protocol.is_empty() {
                return Err(Error::InvalidLength("alpn protocol must not be empty"));
            }
            if protocol.len() > u8::MAX as usize {
                return Err(Error::InvalidLength(
                    "alpn protocol length must not exceed 255 bytes",
                ));
            }
            let protocols = vec![protocol.to_vec()];
            let extension_data = noxtls_encode_alpn_extension_data(&protocols)?;
            noxtls_push_extension(&mut extensions, EXT_ALPN, &extension_data);
        }
        if acknowledge_server_name {
            noxtls_push_extension(&mut extensions, EXT_SERVER_NAME, &[]);
        }
        if accept_early_data {
            noxtls_push_extension(&mut extensions, EXT_EARLY_DATA, &[]);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_ENCRYPTED_EXTENSIONS,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 Certificate handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded Certificate handshake message.
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
    pub fn noxtls_recv_certificate(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerEncryptedExtensionsReceived
            && self.state != HandshakeState::ServerCertificateRequestReceived
        {
            return Err(Error::StateError(
                "certificate can only be processed after encrypted extensions/certificate request",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_CERTIFICATE {
            return Err(Error::ParseFailure("invalid certificate type"));
        }
        let parsed = noxtls_parse_certificate_body(body)?;
        self.noxtls_tls13_server_ocsp_staple = parsed.leaf_ocsp_staple.clone();
        self.noxtls_tls13_server_ocsp_staple_verified = false;
        if self.tls13_require_ocsp_staple && parsed.leaf_ocsp_staple.is_none() {
            return Err(Error::ParseFailure(
                "certificate message missing required ocsp staple",
            ));
        }
        if let Some(staple) = parsed.leaf_ocsp_staple.as_deref() {
            if let Some(verifier) = self.tls13_ocsp_staple_verifier {
                match verifier(staple)? {
                    Tls13OcspStapleVerification::Good => {
                        self.noxtls_tls13_server_ocsp_staple_verified = true;
                    }
                    Tls13OcspStapleVerification::Expired => {
                        return Err(Error::ParseFailure("ocsp staple expired"));
                    }
                    Tls13OcspStapleVerification::Revoked => {
                        return Err(Error::ParseFailure("ocsp staple revoked"));
                    }
                }
            } else {
                self.noxtls_tls13_server_ocsp_staple_verified = true;
            }
        }
        if self.tls13_require_certificate_auth {
            self.noxtls_validate_tls13_server_certificate_chain(&parsed.certificates)?;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateReceived;
        Ok(())
    }

    /// Processes a full server handshake flight in expected TLS 1.3 order.
    ///
    /// Expected sequence:
    /// * `ServerHello`
    /// * `EncryptedExtensions`
    /// * optional `CertificateRequest`
    /// * `Certificate`
    /// * `CertificateVerify`
    /// * `Finished`
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from server.
    ///
    /// # Returns
    /// `Ok(())` when the full flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_server_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()> {
        if messages.len() < 5 {
            return Err(Error::ParseFailure("server handshake flight is too short"));
        }
        let mut index = 0_usize;
        self.noxtls_recv_server_hello(&messages[index])?;
        index += 1;
        self.noxtls_derive_handshake_secret()?;
        self.noxtls_recv_encrypted_extensions(&messages[index])?;
        index += 1;
        let (next_type, _) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type == HANDSHAKE_CERTIFICATE_REQUEST {
            self.noxtls_recv_certificate_request(&messages[index])?;
            index += 1;
        }
        self.noxtls_recv_certificate(&messages[index])?;
        index += 1;
        self.noxtls_recv_certificate_verify(&messages[index])?;
        index += 1;
        self.noxtls_recv_finished_message(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing server handshake messages",
            ));
        }
        Ok(())
    }

    /// Decrypts TLS 1.3 server post-`ServerHello` records and completes the canonical server handshake flight.
    ///
    /// Callers must have sent `ClientHello` and processed plaintext `ServerHello` so the transcript hash
    /// through `ServerHello` matches RFC 8446 handshake traffic key derivation inputs.
    ///
    /// # Arguments
    ///
    /// * `packets` — Ordered TLS 1.3 `application_data` ciphertext record bytes (one outer record per element).
    /// * `aad` — AEAD additional data for each record (often empty when integrating minimal transports).
    ///
    /// # Returns
    ///
    /// `Ok(())` when decrypted handshake messages match the strict ordering enforced by
    /// [`Connection::noxtls_process_server_handshake_flight`].
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when decryption, parsing, or handshake policy checks fail.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_process_tls13_server_encrypted_handshake_flight(
        &mut self,
        packets: &[Vec<u8>],
        aad: &[u8],
    ) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() || self.version.is_dtls() {
            return Err(Error::StateError(
                "tls13 encrypted server flight requires tls 1.3 non-dtls connection",
            ));
        }
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(Error::StateError(
                "tls13 encrypted server flight requires server hello received state",
            ));
        }
        self.noxtls_derive_handshake_secret()?;
        let mut messages = Vec::new();
        for packet in packets {
            let (inner, content_type) = self.noxtls_open_tls13_record_packet(packet, aad)?;
            if content_type != RecordContentType::Handshake.to_u8() {
                return Err(Error::ParseFailure(
                    "tls13 encrypted server flight inner record must be handshake",
                ));
            }
            let parts = split_tls13_handshake_payload(&inner)?;
            messages.extend(parts);
        }
        if messages.len() < 4 {
            return Err(Error::ParseFailure(
                "tls13 decrypted server handshake flight is too short",
            ));
        }
        let mut index = 0_usize;
        self.noxtls_recv_encrypted_extensions(&messages[index])?;
        index += 1;
        let (next_type, _) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type == HANDSHAKE_CERTIFICATE_REQUEST {
            self.noxtls_recv_certificate_request(&messages[index])?;
            index += 1;
        }
        self.noxtls_recv_certificate(&messages[index])?;
        index += 1;
        self.noxtls_recv_certificate_verify(&messages[index])?;
        index += 1;
        self.noxtls_recv_finished_message(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing tls13 decrypted server handshake messages",
            ));
        }
        Ok(())
    }
}
