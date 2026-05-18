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

//! TLS 1.3 server-role handshake orchestration and identity configuration.

use super::super::tls_wire::TLS_RECORD_HEADER_LEN;
use super::*;

impl Connection {
    /// Creates a TLS 1.3 server-role connection in the `Idle` handshake state.
    ///
    /// # Arguments
    ///
    /// _(none)_ — Uses [`TlsVersion::Tls13`] and [`TlsRole::Server`].
    ///
    /// # Returns
    ///
    /// A fresh server `Connection` with a default TLS 1.3 cipher-suite preference list.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_new_tls13_server() -> Self {
        let mut conn = Self::noxtls_new(TlsVersion::Tls13);
        conn.tls_role = TlsRole::Server;
        conn.tls13_server_preferred_cipher_suites = vec![
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsAes256GcmSha384,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ];
        conn.tls13_server_alpn_protocols = vec![b"http/1.1".to_vec()];
        conn
    }

    /// Configures server-offered TLS 1.3 cipher suites in preference order.
    ///
    /// # Arguments
    ///
    /// * `suites` — Non-empty preference-ordered cipher suite list.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the preference list is stored.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when `suites` is empty.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_set_tls13_server_cipher_suites(&mut self, suites: &[CipherSuite]) -> Result<()> {
        if suites.is_empty() {
            return Err(Error::InvalidLength(
                "server cipher suite preference list must not be empty",
            ));
        }
        self.tls13_server_preferred_cipher_suites = suites.to_vec();
        Ok(())
    }

    /// Configures ALPN protocols the server is willing to select during handshake.
    ///
    /// # Arguments
    ///
    /// * `protocols` — Preference-ordered ALPN protocol identifiers.
    ///
    /// # Returns
    ///
    /// `Ok(())` after storing the protocol list.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when any protocol identifier is empty or too long.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_set_tls13_server_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        let mut stored = Vec::with_capacity(protocols.len());
        for protocol in protocols {
            if protocol.is_empty() {
                return Err(Error::InvalidLength("alpn protocol must not be empty"));
            }
            if protocol.len() > u8::MAX as usize {
                return Err(Error::InvalidLength(
                    "alpn protocol length must not exceed 255 bytes",
                ));
            }
            stored.push(protocol.to_vec());
        }
        self.tls13_server_alpn_protocols = stored;
        Ok(())
    }

    /// Installs the TLS 1.3 server leaf/intermediate certificate chain and signing key.
    ///
    /// # Arguments
    ///
    /// * `certificate_chain_der` — DER-encoded certificates with the leaf first.
    /// * `signing_key` — Private key used to sign `CertificateVerify`.
    ///
    /// # Returns
    ///
    /// `Ok(())` after leaf SPKI material is cached for handshake signing.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when the chain is empty or the leaf certificate cannot be parsed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_configure_tls13_server_identity(
        &mut self,
        certificate_chain_der: &[Vec<u8>],
        signing_key: Tls13ServerIdentityKey,
    ) -> Result<()> {
        if certificate_chain_der.is_empty() {
            return Err(Error::InvalidLength(
                "server certificate chain must contain at least one certificate",
            ));
        }
        let leaf = noxtls_parse_certificate(&certificate_chain_der[0])?;
        self.tls13_server_certificate_chain_der = certificate_chain_der.to_vec();
        self.tls13_server_signing_key = Some(signing_key);
        self.tls13_server_leaf_public_key_der = Some(leaf.subject_public_key);
        self.tls13_server_certificate_chain_validated = true;
        Ok(())
    }

    /// Parses a ClientHello, negotiates parameters, and builds a ServerHello message.
    ///
    /// # Arguments
    ///
    /// * `client_hello` — Encoded ClientHello handshake message bytes.
    /// * `server_random` — 32-byte ServerHello random value.
    ///
    /// # Returns
    ///
    /// On success, encoded ServerHello handshake message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called outside server role, handshake state is invalid,
    /// cipher-suite negotiation fails, or key-share negotiation fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_accept_tls13_client_hello(
        &mut self,
        client_hello: &[u8],
        server_random: &[u8],
    ) -> Result<Vec<u8>> {
        if self.tls_role != TlsRole::Server {
            return Err(Error::StateError(
                "client hello acceptance requires server-role connection",
            ));
        }
        if self.state != HandshakeState::Idle {
            return Err(Error::StateError(
                "client hello can only be accepted from idle server state",
            ));
        }
        if server_random.len() != 32 {
            return Err(Error::InvalidLength("server hello random must be 32 bytes"));
        }
        if self.tls13_server_certificate_chain_der.is_empty()
            || self.tls13_server_signing_key.is_none()
        {
            return Err(Error::StateError(
                "server identity must be configured before accepting client hello",
            ));
        }
        let preferred = if self.tls13_server_preferred_cipher_suites.is_empty() {
            noxtls_default_client_cipher_suites(self.version)
        } else {
            self.tls13_server_preferred_cipher_suites.clone()
        };
        let hello_info = Self::noxtls_parse_client_hello_info(client_hello)?;
        let selected =
            Self::noxtls_select_cipher_suite_from_client_hello(client_hello, &preferred, self.version)?;
        self.tls13_client_server_name = hello_info.extensions.sni_server_name.clone();
        self.tls13_client_alpn_protocols = hello_info.extensions.alpn_protocols.clone();
        self.noxtls_reset_transcript_for_new_handshake();
        self.noxtls_append_transcript(client_hello);
        self.noxtls_selected_cipher_suite = Some(selected);
        self.noxtls_rebuild_transcript_hash_from_selected_suite();

        let (group, shared_secret, server_key_exchange) =
            self.noxtls_negotiate_tls13_server_key_share(client_hello, server_random)?;
        self.tls13_shared_secret = Some(shared_secret);
        let (_, client_hello_body) = noxtls_parse_handshake_message(client_hello)?;
        let legacy_session_id = noxtls_extract_client_hello_legacy_session_id(client_hello_body)?;
        let server_hello = Self::noxtls_build_server_hello_with_key_share(
            self.version,
            selected,
            server_random,
            group,
            &server_key_exchange,
            Some(legacy_session_id),
        )?;
        self.noxtls_append_transcript(&server_hello);
        self.state = HandshakeState::ServerHelloSent;
        Ok(server_hello)
    }

    /// Builds and seals the TLS 1.3 server encrypted handshake flight.
    ///
    /// The returned packet contains EncryptedExtensions, Certificate, CertificateVerify, and
    /// Finished handshake messages sealed with the server handshake traffic keys.
    ///
    /// # Arguments
    ///
    /// * `self` — Server connection in `KeysDerived` state after handshake-secret derivation.
    ///
    /// # Returns
    ///
    /// On success, one TLS 1.3 `application_data` record packet carrying the encrypted flight.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when handshake state is invalid or message construction fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_build_tls13_server_handshake_flight(&mut self) -> Result<Vec<u8>> {
        if self.tls_role != TlsRole::Server {
            return Err(Error::StateError(
                "server handshake flight requires server-role connection",
            ));
        }
        if self.state != HandshakeState::KeysDerived {
            return Err(Error::StateError(
                "server handshake flight requires keys derived state",
            ));
        }
        let selected_alpn = self.noxtls_pick_server_alpn_protocol();
        let acknowledge_sni = self.tls13_client_server_name.is_some();
        let encrypted_extensions = Self::noxtls_build_encrypted_extensions_with_policy(
            selected_alpn.as_deref(),
            acknowledge_sni,
            false,
        )?;
        self.noxtls_append_transcript(&encrypted_extensions);

        let leaf_cert = self
            .tls13_server_certificate_chain_der
            .first()
            .ok_or(Error::StateError("server certificate chain is not configured"))?
            .clone();
        let certificate = Self::noxtls_build_certificate_message(&leaf_cert)?;
        self.noxtls_append_transcript(&certificate);

        let certificate_verify = self.noxtls_build_server_certificate_verify_handshake_message()?;
        self.noxtls_append_transcript(&certificate_verify);

        let finished = self.noxtls_build_finished_message()?;
        self.noxtls_append_transcript(&finished);

        let mut handshake_payload = Vec::new();
        handshake_payload.extend_from_slice(&encrypted_extensions);
        handshake_payload.extend_from_slice(&certificate);
        handshake_payload.extend_from_slice(&certificate_verify);
        handshake_payload.extend_from_slice(&finished);

        let aad = self.noxtls_build_tls13_server_handshake_record_aad(handshake_payload.len())?;
        self.noxtls_seal_server_tls13_record_packet(
            &handshake_payload,
            RecordContentType::Handshake.to_u8(),
            &aad,
            0,
        )
    }

    /// Verifies and records a client Finished handshake message.
    ///
    /// # Arguments
    ///
    /// * `msg` — Encoded Finished handshake message from the client.
    ///
    /// # Returns
    ///
    /// `Ok(())` when verify data matches and state transitions to `Finished`.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when verify data is invalid or handshake state is wrong.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_recv_client_finished_message(&mut self, msg: &[u8]) -> Result<()> {
        if self.tls_role != TlsRole::Server {
            return Err(Error::StateError(
                "client finished processing requires server-role connection",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_FINISHED {
            return Err(Error::ParseFailure("invalid finished type"));
        }
        if self.state != HandshakeState::KeysDerived {
            return Err(Error::StateError(
                "client finished can only be processed after server handshake flight",
            ));
        }
        let expected = self.noxtls_compute_expected_client_finished()?;
        if body.len() != expected.len() {
            return Err(Error::ParseFailure("finished verify_data length mismatch"));
        }
        if !noxtls_constant_time_eq(body, &expected) {
            return Err(Error::CryptoFailure("client finished verify_data mismatch"));
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::Finished;
        Ok(())
    }

    /// Opens one client Finished handshake message from an encrypted TLS 1.3 record packet.
    ///
    /// # Arguments
    ///
    /// * `packet` — Encrypted TLS 1.3 record packet from the client.
    ///
    /// # Returns
    ///
    /// `Ok(())` after the Finished message is authenticated and recorded.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when record decryption or Finished verification fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_recv_client_finished_packet(&mut self, packet: &[u8]) -> Result<()> {
        let aad = Self::noxtls_tls13_packet_header_aad(packet)?;
        let (inner, content_type) = self.noxtls_open_client_tls13_record_packet(packet, &aad)?;
        if content_type != RecordContentType::Handshake.to_u8() {
            return Err(Error::ParseFailure(
                "expected handshake content in client finished record",
            ));
        }
        let messages = split_tls13_handshake_payload(&inner)?;
        let finished = messages
            .last()
            .ok_or(Error::ParseFailure("client finished record missing handshake message"))?;
        self.noxtls_recv_client_finished_message(finished)
    }

    /// Returns a stable display name for the negotiated cipher suite.
    ///
    /// # Arguments
    ///
    /// * `&self` — Connection with a selected cipher suite.
    ///
    /// # Returns
    ///
    /// `Some` human-readable suite label when negotiation completed; otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_cipher_suite_display_name(&self) -> Option<&'static str> {
        self.noxtls_selected_cipher_suite.map(|suite| match suite {
            CipherSuite::TlsAes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::TlsAes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::TlsChacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        })
    }

    /// Negotiates server key share material against a ClientHello and returns shared secret bytes.
    ///
    /// # Arguments
    ///
    /// * `client_hello` — Encoded ClientHello handshake message bytes.
    /// * `server_random` — 32-byte ServerHello random used for deterministic key generation.
    ///
    /// # Returns
    ///
    /// On success, `(named_group, shared_secret, server_key_exchange_bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when no compatible key share is offered.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_negotiate_tls13_server_key_share(
        &mut self,
        client_hello: &[u8],
        server_random: &[u8],
    ) -> Result<(u16, Vec<u8>, Vec<u8>)> {
        if let Some(peer_key) =
            noxtls_extract_tls13_client_hello_key_share(client_hello, TLS13_KEY_SHARE_GROUP_X25519)?
        {
            let private =
                noxtls_derive_deterministic_x25519_private(server_random, b"tls13 server x25519");
            let public = private.public_key().bytes;
            let shared = noxtls_derive_tls13_x25519_shared_secret(private, &peer_key)?.to_vec();
            self.tls13_server_x25519_private = None;
            self.tls13_server_p256_private = None;
            return Ok((
                TLS13_KEY_SHARE_GROUP_X25519,
                shared,
                public.to_vec(),
            ));
        }
        if let Some(peer_key) = noxtls_extract_tls13_client_hello_key_share(
            client_hello,
            TLS13_KEY_SHARE_GROUP_SECP256R1,
        )? {
            let private =
                noxtls_derive_deterministic_p256_private(server_random, b"tls13 server secp256r1")?;
            let public = private.public_key()?.to_uncompressed()?;
            let shared = noxtls_derive_tls13_p256_shared_secret(&private, &peer_key)?.to_vec();
            self.tls13_server_p256_private = Some(private);
            self.tls13_server_x25519_private = None;
            return Ok((
                TLS13_KEY_SHARE_GROUP_SECP256R1,
                shared,
                public.to_vec(),
            ));
        }
        Err(Error::ParseFailure(
            "client hello does not offer a supported x25519 or secp256r1 key share",
        ))
    }

    /// Picks the first mutually acceptable ALPN protocol for the server role.
    ///
    /// # Arguments
    ///
    /// * `&self` — Server connection with stored client and server ALPN offers.
    ///
    /// # Returns
    ///
    /// Selected ALPN protocol bytes when one intersects; otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_pick_server_alpn_protocol(&mut self) -> Option<Vec<u8>> {
        for preferred in &self.tls13_server_alpn_protocols {
            if self.tls13_client_alpn_protocols.contains(preferred) {
                self.noxtls_tls13_selected_alpn_protocol = Some(preferred.clone());
                return Some(preferred.clone());
            }
        }
        None
    }

    /// Builds a TLS 1.3 CertificateVerify handshake message for the configured server identity.
    ///
    /// # Arguments
    ///
    /// * `&self` — Server connection with transcript and signing key configured.
    ///
    /// # Returns
    ///
    /// On success, encoded CertificateVerify handshake message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when signing material is missing or signature encoding fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_build_server_certificate_verify_handshake_message(&self) -> Result<Vec<u8>> {
        let signing_key = self
            .tls13_server_signing_key
            .as_ref()
            .ok_or(Error::StateError("server signing key is not configured"))?;
        let signed_message =
            noxtls_build_tls13_server_certificate_verify_message(&self.noxtls_transcript_hash());
        let (signature_scheme, signature) = match signing_key {
            Tls13ServerIdentityKey::P256(private_key) => {
                let (r, s) = noxtls_p256_ecdsa_sign_sha256(private_key, &signed_message)?;
                let mut signature = Vec::with_capacity(64);
                signature.extend_from_slice(&r);
                signature.extend_from_slice(&s);
                (TLS13_SIGALG_ECDSA_SECP256R1_SHA256, signature)
            }
            Tls13ServerIdentityKey::Rsa(private_key) => {
                let hash = self.noxtls_transcript_hash();
                let mut salt = [0_u8; 32];
                let copy_len = hash.len().min(32);
                salt[..copy_len].copy_from_slice(&hash[..copy_len]);
                let signature =
                    noxtls_rsassa_pss_sha256_sign(private_key, &signed_message, &salt)?;
                (TLS13_SIGALG_RSA_PSS_RSAE_SHA256, signature)
            }
        };
        Self::noxtls_build_certificate_verify_message(signature_scheme, &signature)
    }

    /// Builds TLS 1.3 outer-record AAD for one outbound server handshake record.
    ///
    /// # Arguments
    ///
    /// * `inner_plaintext_len` — Length of TLSInnerPlaintext bytes including content-type and padding.
    ///
    /// # Returns
    ///
    /// On success, five-byte TLS record header used as AEAD AAD.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when payload length overflows `u16`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_build_tls13_server_handshake_record_aad(
        &self,
        inner_plaintext_len: usize,
    ) -> Result<[u8; TLS_RECORD_HEADER_LEN]> {
        let payload_len = inner_plaintext_len
            .checked_add(1)
            .and_then(|v| v.checked_add(TLS13_RECORD_TAG_LEN))
            .ok_or(Error::InvalidLength(
                "tls13 server handshake payload length overflow",
            ))?;
        let payload_len_u16 = u16::try_from(payload_len)
            .map_err(|_| Error::InvalidLength("tls13 server handshake payload exceeds u16 length"))?;
        let mut aad = [0_u8; TLS_RECORD_HEADER_LEN];
        aad[0] = RecordContentType::ApplicationData.to_u8();
        aad[1] = 0x03;
        aad[2] = 0x03;
        aad[3..5].copy_from_slice(&payload_len_u16.to_be_bytes());
        Ok(aad)
    }

    /// Parses a TLS 1.3 packet header into AEAD additional authenticated data.
    ///
    /// # Arguments
    ///
    /// * `packet` — Serialized TLS 1.3 record packet bytes.
    ///
    /// # Returns
    ///
    /// On success, five-byte record header used as AEAD AAD.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when the packet is truncated or length fields disagree.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_tls13_packet_header_aad(packet: &[u8]) -> Result<[u8; TLS_RECORD_HEADER_LEN]> {
        if packet.len() < TLS_RECORD_HEADER_LEN {
            return Err(Error::ParseFailure("tls13 packet too short for header"));
        }
        let mut aad = [0_u8; TLS_RECORD_HEADER_LEN];
        aad.copy_from_slice(&packet[..TLS_RECORD_HEADER_LEN]);
        let payload_len = u16::from_be_bytes([aad[3], aad[4]]) as usize;
        if packet.len() != TLS_RECORD_HEADER_LEN.saturating_add(payload_len) {
            return Err(Error::ParseFailure("tls13 packet length mismatch"));
        }
        Ok(aad)
    }
}

/// Extracts one ClientHello `key_share` entry for the requested named group.
///
/// # Arguments
///
/// * `message` — Encoded ClientHello handshake message bytes.
/// * `group` — Requested TLS NamedGroup identifier.
///
/// # Returns
///
/// `Ok(Some(key_exchange))` when the group is present; otherwise `Ok(None)`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when handshake framing or extension encoding is malformed.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_extract_tls13_client_hello_key_share(
    message: &[u8],
    group: u16,
) -> Result<Option<Vec<u8>>> {
    let (handshake_type, body) = noxtls_parse_handshake_message(message)?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return Err(Error::ParseFailure(
            "expected client hello while extracting key share",
        ));
    }
    if body.len() < 39 {
        return Err(Error::ParseFailure("client hello body too short"));
    }
    let mut offset = 0_usize;
    offset = offset.saturating_add(2);
    offset = offset.saturating_add(32);
    let session_id_len = body
        .get(offset)
        .copied()
        .ok_or(Error::ParseFailure("client hello missing session_id length"))?
        as usize;
    offset = offset.saturating_add(1 + session_id_len);
    if body.len().saturating_sub(offset) < 2 {
        return Err(Error::ParseFailure(
            "client hello missing cipher_suites length",
        ));
    }
    let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset = offset.saturating_add(2 + suites_len);
    if body.len().saturating_sub(offset) < 1 {
        return Err(Error::ParseFailure(
            "client hello missing compression_methods length",
        ));
    }
    let compression_len = body[offset] as usize;
    offset = offset.saturating_add(1 + compression_len);
    if body.len().saturating_sub(offset) < 2 {
        return Err(Error::ParseFailure("client hello missing extensions length"));
    }
    let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset = offset.saturating_add(2);
    if body.len().saturating_sub(offset) < extensions_len {
        return Err(Error::ParseFailure("client hello extensions truncated"));
    }
    let mut cursor = &body[offset..offset + extensions_len];
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "client hello extension header truncated",
            ));
        }
        let extension_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let extension_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        if cursor.len() < extension_len {
            return Err(Error::ParseFailure("client hello extension truncated"));
        }
        let extension_data = &cursor[..extension_len];
        if extension_type == EXT_KEY_SHARE {
            if extension_data.len() < 2 {
                return Err(Error::ParseFailure(
                    "client hello key_share extension missing vector length",
                ));
            }
            let key_share_list_len =
                u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
            if extension_data.len() != key_share_list_len + 2 {
                return Err(Error::ParseFailure(
                    "client hello key_share extension length mismatch",
                ));
            }
            let mut shares = &extension_data[2..];
            while !shares.is_empty() {
                if shares.len() < 4 {
                    return Err(Error::ParseFailure("client hello key_share entry truncated"));
                }
                let entry_group = u16::from_be_bytes([shares[0], shares[1]]);
                let key_exchange_len = u16::from_be_bytes([shares[2], shares[3]]) as usize;
                shares = &shares[4..];
                if shares.len() < key_exchange_len {
                    return Err(Error::ParseFailure(
                        "client hello key_share key_exchange truncated",
                    ));
                }
                if entry_group == group {
                    return Ok(Some(shares[..key_exchange_len].to_vec()));
                }
                shares = &shares[key_exchange_len..];
            }
            return Ok(None);
        }
        cursor = &cursor[extension_len..];
    }
    Ok(None)
}

const TLS13_RECORD_TAG_LEN: usize = 16;
