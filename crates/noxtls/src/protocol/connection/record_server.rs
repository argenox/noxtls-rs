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

//! TLS 1.3 server-direction record seal/open helpers (server writes, client reads).

use super::*;

impl Connection {
    /// Seals outbound application or handshake data using installed server traffic keys.
    ///
    /// # Arguments
    ///
    /// * `plaintext` — Bytes to encrypt and authenticate.
    /// * `aad` — Additional authenticated data bound to the AEAD operation.
    ///
    /// # Returns
    ///
    /// On success, a [`ProtectedRecord`] sealed with the server write key and IV.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when handshake state, suite, or key material is invalid.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_seal_server_record(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<ProtectedRecord> {
        let handshake_seal_allowed = self.version.uses_tls13_handshake_semantics()
            && self.tls_role == TlsRole::Server
            && self.state == HandshakeState::KeysDerived;
        if self.state != HandshakeState::Finished && !handshake_seal_allowed {
            return Err(Error::StateError(
                "cannot seal server record before handshake completion or tls13 server handshake flight",
            ));
        }
        if plaintext.len() > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        if self.server_sequence == u64::MAX {
            return Err(Error::StateError("server record sequence exhausted"));
        }
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before sealing server records",
        ))?;
        let key = self
            .server_write_key
            .ok_or(Error::StateError("server write key is not installed"))?;
        let iv = self
            .server_write_iv
            .ok_or(Error::StateError("server write iv is not installed"))?;
        let nonce = noxtls_build_record_nonce(&iv, self.server_sequence);
        let (ciphertext, tag) = Self::noxtls_aead_encrypt_for_suite(suite, &key, &nonce, aad, plaintext)?;
        let record = ProtectedRecord {
            sequence: self.server_sequence,
            ciphertext,
            tag,
        };
        self.server_sequence = self.server_sequence.wrapping_add(1);
        Ok(record)
    }

    /// Opens inbound data sealed by the TLS peer using installed client traffic keys.
    ///
    /// # Arguments
    ///
    /// * `record` — Protected record received from the client.
    /// * `aad` — Additional authenticated data used when the peer sealed the record.
    ///
    /// # Returns
    ///
    /// On success, decrypted plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] on authentication failure, sequence mismatch, or invalid state.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_open_client_record(
        &mut self,
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let tls13_handshake_open_allowed = self.version.uses_tls13_handshake_semantics()
            && self.tls_role == TlsRole::Server
            && self.state == HandshakeState::KeysDerived;
        if self.state != HandshakeState::Finished && !tls13_handshake_open_allowed {
            return Err(Error::StateError(
                "cannot open client record before handshake completion or tls13 server handshake flight",
            ));
        }
        if self.client_sequence == u64::MAX {
            return Err(Error::StateError("client record sequence exhausted"));
        }
        if record.sequence != self.client_sequence {
            return Err(Error::StateError(
                "unexpected client record sequence number",
            ));
        }
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before opening client records",
        ))?;
        let key = self
            .client_write_key
            .ok_or(Error::StateError("client write key is not installed"))?;
        let iv = self
            .client_write_iv
            .ok_or(Error::StateError("client write iv is not installed"))?;
        let nonce = noxtls_build_record_nonce(&iv, record.sequence);
        let plaintext =
            Self::noxtls_aead_decrypt_for_suite(suite, &key, &nonce, aad, &record.ciphertext, &record.tag)?;
        if plaintext.len() > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        self.client_sequence = self.client_sequence.wrapping_add(1);
        Ok(plaintext)
    }

    /// Seals one TLS 1.3 inner record using server traffic keys.
    ///
    /// # Arguments
    ///
    /// * `content` — Inner plaintext content bytes.
    /// * `content_type` — TLSInnerPlaintext content type byte.
    /// * `aad` — Record header bytes used as AEAD additional data.
    /// * `padding_len` — Number of trailing zero padding bytes.
    ///
    /// # Returns
    ///
    /// On success, a protected record using the server write key.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called outside TLS 1.3 or when seal preconditions fail.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_seal_server_tls13_inner_record(
        &mut self,
        content: &[u8],
        content_type: u8,
        aad: &[u8],
        padding_len: usize,
    ) -> Result<ProtectedRecord> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 inner plaintext records require TLS 1.3 connection",
            ));
        }
        let inner = noxtls_encode_tls13_inner_plaintext(content, content_type, padding_len);
        self.noxtls_seal_server_record(&inner, aad)
    }

    /// Opens one TLS 1.3 inner record sealed by the client and decodes TLSInnerPlaintext.
    ///
    /// # Arguments
    ///
    /// * `record` — Protected record received from the client.
    /// * `aad` — Record header bytes used as AEAD additional data.
    ///
    /// # Returns
    ///
    /// On success, `(content, content_type)` extracted from the inner plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when decryption or inner-plaintext parsing fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_open_client_tls13_inner_record(
        &mut self,
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<(Vec<u8>, u8)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 inner plaintext records require TLS 1.3 connection",
            ));
        }
        let inner = self.noxtls_open_client_record(record, aad)?;
        noxtls_decode_tls13_inner_plaintext(&inner)
    }

    /// Seals one TLS 1.3 wire record packet using server traffic keys.
    ///
    /// # Arguments
    ///
    /// * `content` — Inner plaintext content bytes.
    /// * `content_type` — TLSInnerPlaintext content type byte.
    /// * `aad` — Record header bytes used as AEAD additional data.
    /// * `padding_len` — Number of trailing zero padding bytes.
    ///
    /// # Returns
    ///
    /// On success, serialized TLSCiphertext packet bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called outside TLS 1.3 or when seal preconditions fail.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_seal_server_tls13_record_packet(
        &mut self,
        content: &[u8],
        content_type: u8,
        aad: &[u8],
        padding_len: usize,
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 record packets require TLS 1.3 connection",
            ));
        }
        let record =
            self.noxtls_seal_server_tls13_inner_record(content, content_type, aad, padding_len)?;
        self.noxtls_encode_tls13_record_packet(&record)
    }

    /// Opens one inbound TLS 1.3 wire record packet sealed by the client.
    ///
    /// # Arguments
    ///
    /// * `packet` — Serialized TLSCiphertext packet bytes from the client.
    /// * `aad` — Record header bytes used as AEAD additional data.
    ///
    /// # Returns
    ///
    /// On success, `(content, content_type)` decoded from the inner plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when decryption or packet framing fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_open_client_tls13_record_packet(
        &mut self,
        packet: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, u8)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 record packets require TLS 1.3 connection",
            ));
        }
        let record = self.noxtls_decode_tls13_record_packet(packet, self.client_sequence)?;
        self.noxtls_open_client_tls13_inner_record(&record, aad)
    }

    /// Encrypts plaintext with the negotiated suite using the provided key and nonce.
    ///
    /// # Arguments
    ///
    /// * `suite` — Negotiated AEAD cipher suite.
    /// * `key` — Up to 32 bytes of key material; AES suites use a prefix slice.
    /// * `nonce` — 12-byte record nonce.
    /// * `aad` — Additional authenticated data.
    /// * `plaintext` — Plaintext bytes to protect.
    ///
    /// # Returns
    ///
    /// On success, `(ciphertext, tag)` for the protected payload.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when cipher construction or AEAD encryption fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_aead_encrypt_for_suite(
        suite: CipherSuite,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        match suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                noxtls_chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
            }
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
                    "tls 1.3 aes suites must define traffic key length",
                ))?;
                let cipher = AesCipher::noxtls_new(&key[..key_len])?;
                noxtls_aes_gcm_encrypt(&cipher, nonce, aad, plaintext)
            }
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                let cipher = AesCipher::noxtls_new(&key[..16])?;
                noxtls_aes_gcm_encrypt(&cipher, nonce, aad, plaintext)
            }
        }
    }

    /// Decrypts ciphertext with the negotiated suite using the provided key and nonce.
    ///
    /// # Arguments
    ///
    /// * `suite` — Negotiated AEAD cipher suite.
    /// * `key` — Up to 32 bytes of key material; AES suites use a prefix slice.
    /// * `nonce` — 12-byte record nonce.
    /// * `aad` — Additional authenticated data.
    /// * `ciphertext` — Protected ciphertext bytes.
    /// * `tag` — 16-byte authentication tag.
    ///
    /// # Returns
    ///
    /// On success, decrypted plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when authentication or cipher operations fail.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub(super) fn noxtls_aead_decrypt_for_suite(
        suite: CipherSuite,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>> {
        match suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                noxtls_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag)
            }
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
                    "tls 1.3 aes suites must define traffic key length",
                ))?;
                let cipher = AesCipher::noxtls_new(&key[..key_len])?;
                noxtls_aes_gcm_decrypt(&cipher, nonce, aad, ciphertext, tag)
            }
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                let cipher = AesCipher::noxtls_new(&key[..16])?;
                noxtls_aes_gcm_decrypt(&cipher, nonce, aad, ciphertext, tag)
            }
        }
    }
}
